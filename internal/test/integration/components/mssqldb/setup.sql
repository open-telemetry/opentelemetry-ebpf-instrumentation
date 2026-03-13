CREATE DATABASE testdb;
GO
USE testdb;
GO
CREATE TABLE actor (
    actor_id INT PRIMARY KEY,
    first_name VARCHAR(50),
    last_name VARCHAR(50)
);
GO
INSERT INTO actor (actor_id, first_name, last_name) VALUES (1, 'TOM', 'CRUISE');
GO
