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

-- bulk_actor has 50 rows with padded names so the SELECT * response exceeds the
-- default 4096-byte TDS packet boundary and forces a multi-packet server response.
CREATE TABLE bulk_actor (
    actor_id   INT PRIMARY KEY,
    first_name VARCHAR(50),
    last_name  VARCHAR(50)
);
GO
DECLARE @i INT = 1;
WHILE @i <= 50
BEGIN
    INSERT INTO bulk_actor (actor_id, first_name, last_name)
    VALUES (@i,
            LEFT(REPLICATE('A', 48), 48),
            LEFT(REPLICATE('B', 48), 48));
    SET @i = @i + 1;
END;
GO
