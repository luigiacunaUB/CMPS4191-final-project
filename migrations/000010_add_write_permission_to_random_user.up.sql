INSERT INTO users_permissions
VALUES (
    (SELECT id FROM users WHERE email = 'luigi.acuna@gmail.com'),
    (SELECT id FROM permissions WHERE  code = 'books:write')
)
