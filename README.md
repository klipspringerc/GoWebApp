# Entry Task

## Dependencies
* github.com/golang/protobuf/proto
* github.com/go-sql-driver/mysql
* github.com/fatih/pool
* github.com/go-redis/redis
* github.com/go-redis/cache
* github.com/dgrijalva/jwt-go
* github.com/nfnt/resize
* github.com/vmihailenco/msgpack

## Files and Directories
* post.lua : the POST form data for wrk load testing
* post.txt : the POST form data for ab test
* populatedb.go : script to populate MySQL DB
* frontserver.go : script for HTTP server, main() resides here 
* simpletcp.go : script for TCP server
* reqres.pb.go & reqres.proto : protobuf configuration files
* test/testserverload.go : script for load testing simulating 200 different users
* static/image/ : directory for uploaded images
* templates/ : html templates

## MySQL Describe Table

| Field    | Type        | Null | Key | Default | Extra |
|----------|-------------|------|-----|---------|-------|
| username | varchar(20) | NO   | PRI | NULL    |       |
| password | varchar(65) | NO   |     | NULL    |       |
| nickname | varchar(20) | NO   |     | NULL    |       |
| picture  | varchar(24) | NO   |     | NULL    |       |


## Usage
go build
Then run executables simpletcp and frontserver 