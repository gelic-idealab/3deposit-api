set -a
source ./dev.env
set +a
go build -o ./build/api.exe && ./build/api.exe