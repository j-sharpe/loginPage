DROP TABLE IF EXISTS user_information;
DROP TABLE IF EXISTS user_credentials;

CREATE TABLE user_credentials (
    user_no INTEGER PRIMARY KEY NOT NULL,
    email VARCHAR(254),
    password VARCHAR(256),
);

CREATE TABLE user_information (
    FOREIGN KEY(user_no_id) REFERENCES user_credentials(user_no) ON DELETE CASCADE,
    username VARCHAR(20),
    f_name VARCHAR(30),
    l_name VARCHAR(30),
);