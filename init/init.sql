
-- need pgcrypto for anonymization relies on cryptographic primitives that Postgres doesn’t provide by default
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- user table
CREATE TABLE IF NOT EXISTS users (
  user_id        BIGSERIAL PRIMARY KEY,
  first_name     VARCHAR(100),
  last_name      VARCHAR(100),
  username       VARCHAR(64),
  email          VARCHAR(255),
  password_hash  BYTEA NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  anonymized_time  TIMESTAMPTZ,
  anon_tag       VARCHAR(64),
  status         VARCHAR(16) NOT NULL DEFAULT 'active'
);
-- make sure the users are unique 
CREATE UNIQUE INDEX IF NOT EXISTS ux_users_username ON users(username);
-- create admin table 
CREATE TABLE IF NOT EXISTS admins (
  admin_id      BIGSERIAL PRIMARY KEY,
  username      VARCHAR(64) UNIQUE NOT NULL,
  password_hash BYTEA NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- create categories table
CREATE TABLE IF NOT EXISTS categories (
  category_id BIGSERIAL PRIMARY KEY,
  name        VARCHAR(120) UNIQUE NOT NULL
);
-- create products table
CREATE TABLE IF NOT EXISTS products (
  product_id        BIGSERIAL PRIMARY KEY,
  product_name      VARCHAR(255) NOT NULL,
  price             NUMERIC(12,2) NOT NULL,
  discount          NUMERIC(5,2)  NOT NULL DEFAULT 0,
  count_in_stock    INTEGER       NOT NULL DEFAULT 0,
  created_at        TIMESTAMPTZ   NOT NULL DEFAULT now(),
  category_id       BIGINT REFERENCES categories(category_id),
  created_by_user_id BIGINT REFERENCES users(user_id)
);
-- create shipping_addresses table
CREATE TABLE IF NOT EXISTS shipping_addresses (
  shipping_address_id BIGSERIAL PRIMARY KEY,
  user_id             BIGINT NOT NULL REFERENCES users(user_id),
  street              VARCHAR(255),
  city                VARCHAR(120),
  zip                 VARCHAR(20),
  state               VARCHAR(120),
  phone_number        VARCHAR(50)
);
-- create shipping_addresses table
CREATE TABLE IF NOT EXISTS orders (
  order_id            BIGSERIAL PRIMARY KEY,
  user_id             BIGINT NOT NULL REFERENCES users(user_id),
  shipping_address_id BIGINT REFERENCES shipping_addresses(shipping_address_id),
  email_snapshot      VARCHAR(255),
  shipping_name           VARCHAR(255),
  shipping_address           VARCHAR(255),
  shipping_city           VARCHAR(120),
  shipping_state          VARCHAR(120),
  shipping_zip            VARCHAR(20),
  ship_country        CHAR(2),
  tax                 NUMERIC(12,2) NOT NULL DEFAULT 0,
  shipping_price      NUMERIC(12,2) NOT NULL DEFAULT 0,
  is_delivered        BOOLEAN       NOT NULL DEFAULT FALSE,
  is_paid             BOOLEAN       NOT NULL DEFAULT FALSE,
  total_cost          NUMERIC(12,2) NOT NULL,
  purchase_date       TIMESTAMPTZ   NOT NULL DEFAULT now(),
  delivery_date       TIMESTAMPTZ
);
-- order_index_based_user_id database index that makes queries faster for all operations filtering by user_id in the orders table.
CREATE INDEX IF NOT EXISTS order_index_based_user_id ON orders(user_id);

CREATE TABLE IF NOT EXISTS order_items (
  order_item_id BIGSERIAL PRIMARY KEY,
  order_id      BIGINT  NOT NULL REFERENCES orders(order_id) ON DELETE CASCADE,
  product_id    BIGINT  NOT NULL REFERENCES products(product_id),
  quantity           INTEGER NOT NULL,
  price    NUMERIC(12,2) NOT NULL
);
-- order_index_based_items_order_id for fast indexing
CREATE INDEX IF NOT EXISTS order_index_based_items_order_id ON order_items(order_id);

CREATE TABLE IF NOT EXISTS payments (
  payment_id   BIGSERIAL PRIMARY KEY,
  order_id     BIGINT NOT NULL REFERENCES orders(order_id),
  psp_ref      VARCHAR(128),
  last4        CHAR(4),
  billing_name VARCHAR(255),
  billing_address VARCHAR(255),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS index_payments_based_order_id ON payments(order_id);

-- slow sha256 hash
-- returns a lowercase hex SHA-256 hash of a text input when re-hashing multiple times
-- hash_times: extra times to re-hash the value after the initial SHA-256
-- hash_input: the string to hash
CREATE OR REPLACE FUNCTION slow_sha256_hex(hash_input TEXT, hash_times INT)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
-- initialize first hash
DECLARE
  h BYTEA := digest(convert_to(COALESCE(hash_input,''), 'UTF8'), 'sha256');
  -- re-hash loop
  i INT := 0;
BEGIN
  WHILE i < GREATEST(hash_times, 0) LOOP
    h := digest(h, 'sha256');
    i := i + 1;
  END LOOP;
  RETURN lower(encode(h, 'hex'));
END
$$;

-- Anonymization function 
-- computes sha256(input) and then re-hashes that result hash_times times, finally returning a lowercase hex string. You feed both personal data and random salt so the resulting anon_<digest> is unique and irreversible for your anonymization.
CREATE OR REPLACE FUNCTION anonymize_user(anon_user_id BIGINT)
RETURNS VOID
LANGUAGE plpgsql
AS $$
-- before_abc are variables that capture the data before the overwrite
-- anon_label: holds the anonymized label
DECLARE
  before_email   TEXT;
  before_first_name   TEXT;
  before_last_name    TEXT;
  before_username  TEXT;
  before_status  TEXT;
  before_salt    BYTEA;
  before_salthex TEXT;
  before_digest  TEXT;
  anon_label     TEXT;
BEGIN
  -- locking the user row
  SELECT email, first_name, last_name, username, status
    INTO before_email, before_first_name, before_last_name, before_username, before_status
  FROM users
  WHERE user_id = anon_user_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN;
  END IF;

  -- repeated calls won’t generate a new anon tag
  IF before_status = 'erased' OR EXISTS (SELECT 1 FROM users WHERE user_id = anon_user_id AND anonymized_time IS NOT NULL) THEN
    RETURN;
  END IF;

  -- per-erasure salt and anon tag
  before_salt    := gen_random_bytes(32);
  before_salthex := lower(encode(before_salt, 'hex'));
  before_digest  := slow_sha256_hex(
                 COALESCE(before_email,'') || '|' ||
                 COALESCE(before_first_name,'') || '|' ||
                 COALESCE(before_last_name,'')  || '|' ||
                 COALESCE(before_username,'')|| '|' ||
                 before_salthex,
                 30000
               );
  anon_label := 'anon_' || substr(before_digest, 1, 12);

  -- update users
  UPDATE users
     SET first_name    = anon_label,
         last_name     = anon_label,
         username      = anon_label,
         email         = anon_label || '@example.invalid',
         anonymized_time = now(),
         anon_tag      = anon_label,
         status        = 'erased'
   WHERE user_id = anon_user_id;

  -- update shipping_addresses
  UPDATE shipping_addresses
     SET street = anon_label,
         city = NULL,
         state        = NULL,
         zip          = NULL,
         phone_number = anon_label
   WHERE user_id = anon_user_id;

  -- updating orders
  UPDATE orders
     SET email_snapshot = anon_label || '@example.invalid',
         shipping_name      = anon_label,
         shipping_address      = anon_label,
         shipping_city      = NULL,
         shipping_state     = NULL,
         shipping_zip       = NULL
   WHERE user_id = anon_user_id;

  -- updating the payments
  UPDATE payments p
     SET billing_name = anon_label,
         billing_address = anon_label
   FROM orders o
   WHERE o.order_id = p.order_id
     AND o.user_id  = anon_user_id;

END
$$;

-- seeding the database
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM users) THEN
    INSERT INTO users(first_name,last_name,username,email,password_hash)
    VALUES ('Alice','Smith','aliceSmith','alice@email.com','\x01');

    INSERT INTO categories(name) VALUES ('Pants');

    INSERT INTO products(product_name,price,category_id,created_by_user_id)
    VALUES ('Bootcut Jeans',79.00,(SELECT category_id FROM categories WHERE name='Pants'),1);

    INSERT INTO shipping_addresses(user_id,street,city,zip,state,phone_number)
    VALUES (1,'123 Peachtree St','Atlanta','30303','GA','+1-404-123-1234');

    INSERT INTO orders(user_id,shipping_address_id,email_snapshot,shipping_name,shipping_address,shipping_city,shipping_state,shipping_zip,ship_country,tax,shipping_price,is_delivered,is_paid,total_cost)
    VALUES (1,(SELECT shipping_address_id FROM shipping_addresses WHERE user_id=1),
            'alice@email.com','Alice Smith','123 Peachtree St','Atlanta','GA','30303','US',
            6.00,5.00,false,true,90.00);

    INSERT INTO order_items(order_id,product_id,quantity,price)
    VALUES ((SELECT order_id FROM orders WHERE user_id=1 LIMIT 1),
            (SELECT product_id FROM products LIMIT 1),1,79.00);

    INSERT INTO payments(order_id,psp_ref,last4,billing_name,billing_address)
    VALUES ((SELECT order_id FROM orders WHERE user_id=1 LIMIT 1),
            'ch_123','4242','Alice Smith','123 Peachtree St');
  END IF;
END $$;
