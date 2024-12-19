-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(), NOW(), NOW(), $1, $2
)
RETURNING id, created_at, updated_at, email;

-- name: GetUserByEmail :one
SELECT id, created_at, updated_at, email, hashed_password
FROM users
WHERE email = $1;

-- name: CreateChirp :one
INSERT INTO chirps (id, created_at, updated_at, body, user_id)
VALUES (
    gen_random_uuid(), NOW(), NOW(), $1, $2
)
RETURNING *;

-- name: DeleteAllUsers :exec
DELETE FROM users;

-- name: GetChirps :many
SELECT id, created_at, updated_at, body, user_id 
FROM chirps 
ORDER BY created_at ASC;

-- name: GetSingleChirp :one
SELECT id, created_at, updated_at, body, user_id 
FROM chirps 
WHERE id = $1;

-- name: StoreRefreshToken :one
INSERT INTO refresh_tokens (token, created_at, updated_at, user_id, expires_at, revoked_at)
VALUES (
    $1, NOW(), NOW(), $2, $3, NULL
)
RETURNING token, created_at, updated_at, user_id, expires_at;

-- name: GetRefreshToken :one
SELECT token, expires_at, revoked_at, user_id
FROM refresh_tokens
WHERE user_id = $1
AND revoked_at IS NULL 
AND expires_at > NOW();

-- name: RevokeToken :one
UPDATE refresh_tokens
SET revoked_at = NOW(), updated_at = NOW()
WHERE token = $1
RETURNING *;

-- name: GetUserFromRefreshToken :one
SELECT users.* FROM users
JOIN refresh_tokens ON users.id = refresh_tokens.user_id
WHERE refresh_tokens.token = $1
AND revoked_at IS NULL
AND expires_at > NOW();
