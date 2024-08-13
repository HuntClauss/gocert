dev:
	go build -o gocert example/gocert.go

release:
	go build -o gocert -trimpath -buildvcs=false -ldflags "-w" example/gocert.go
