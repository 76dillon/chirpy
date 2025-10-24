# chirpy

#Up/down migrations
goose postgres "postgres://mattdillon:@localhost:5432/chirpy" up/down

#Build and Run
go build -o out && ./out