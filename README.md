#goebpf

Steps to Run

1. Prerequistie - BCC/CLANG and GO language has to be installed in linux HOST
https://github.com/iovisor/bcc/blob/master/INSTALL.md
Go for ubuntu
https://github.com/golang/go/wiki/Ubuntu

2.  running the go file
go mod init examples/perf-ip-send
go run .

3. initiate ping from another terminal as "ping google.com"

4. go run . should print the src-ip/dst-ip/pid ... as follows for each ping.
sip c0a8010d dip 8efa4c4e code 0 type 0 pid 1111 return val 0
