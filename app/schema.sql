DROP TABLE IF EXISTS user_credentials;

CREATE TABLE user_credentials (
    email VARCHAR(254),
    password VARCHAR(256),
    PRIMARY KEY(email)
);