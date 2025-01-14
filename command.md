# xquic cmake 配置命令
cmake -DGCOV=on -DCMAKE_BUILD_TYPE=Debug -DXQC_ENABLE_TESTING=1 -DXQC_SUPPORT_SENDMMSG_BUILD=1 -DXQC_ENABLE_EVENT_LOG=1 -DXQC_ENABLE_BBR2=1 -DXQC_ENABLE_RENO=1 -DSSL_TYPE=${SSL_TYPE_STR} -DSSL_PATH=${SSL_PATH_STR} ..
make -j 
cmake -DBORINGSSL_DIR=$BORINGSSL .
make -j 


# 代码索引设置
1. compile_json配置 
"clangd.arguments": [
   "--compile-commands-dir=/root/workspace/xquic/build/compile_commands.json"
],
"clangd.path": "/usr/bin/clangd-18",
2. 在每个compile_commands项目的根目录中创建.clangd
CompileFlags:
  Add:
    - -I/root/workspace/xquic/include
    - -I/root/workspace/xquic
    
# xquic测试命令

./test_server -l d 
./test_client -a 127.0.0.1 -p 8443 -s 1024000 -E

## client扩展
   -a    Server addr.
   -p    Server port.
   -P    Number of Parallel requests per single connection. Default 1.
   -n    Total number of requests to send. Defaults 1.
   -c    Congestion Control Algorithm. r:reno b:bbr c:cubic B:bbr2 bbr+ bbr2+ P:copa
   -C    Pacing on.
   -t    Connection timeout. Default 3 seconds.
   -T    Transport protocol: 0 H3 (default), 1 Transport layer, 2 H3-ext.
   -1    Force 1RTT.
   -s    Body size to send.
   -F    Abs_timeout to close conn. >=0.
   -w    Write received body to file.
   -r    Read sending body from file. priority s > r
   -l    Log level. e:error d:debug.
   -E    Echo check on. Compare sent data with received data.
   -d    Drop rate ‰.
   -u    Url. default https://test.xquic.com/path/resource
   -H    Header. eg. key:value
   -h    Host & sni. eg. test.xquic.com
   -G    GET on. Default is POST
   -x    Test case ID ikoooo-ips
   -N    No encryption
   -6    IPv6
   -M    Enable multi-path on. |
   -v    Multipath Version Negotiation.
   -i    Multi-path interface. e.g. -i interface1 -i interface2.
   -R    Enable reinjection. Default is 0, no reinjection.
   -V    Force cert verification. 0: don't allow self-signed cert. 1: allow self-signed cert.
   -q    name-value pair num of request header, default and larger than 6
   -o    Output log file path, default ./clog
   -f    Debug endless loop.
   -e    Epoch, default is 0.
   -D    Process num. default is 2.
   -b    Create connection per second. default is 100.
   -B    Max connection num. default is 1000.
   -J    Random CID. default is 0.
   -Q    Multipath backup path standby, set backup_mode on(1). default backup_mode is 0(off).
   -A    Multipath request accelerate on. default is 0(off).
   -y    multipath backup path standby.
   -z    periodically send request.



## server扩展:
   Options:
   -a    Server addr.
   -p    Server port.
   -e    Echo. Send received body.
   -c    Congestion Control Algorithm. r:reno b:bbr c:cubic B:bbr2 bbr+ bbr2+
   -C    Pacing on.
   -L    Endless_sending. default is 0(off).
   -s    Body size to send.
   -w    Write received body to file.
   -r    Read sending body from file. priority e > s > r
   -l    Log level. e:error d:debug.
   -u    Url. default https://test.xquic.com/path/resource
   -x    Test case ID
   -6    IPv6
   -b    batch
   -S    server sid
   -M    Enable multi-path on.
   -R    Enable reinjection. Default is 0, no reinjection.
   -E    load balance id encryption on
   -K    load balance id encryption key
   -o    Output log file path, default ./slog
   -m    Set mpshell on.
   -y    Multipath backup path standby.
   -Q    Multipath backup path standby, set backup_mode on(1). default backup_mode is 0(off).
   -H    Disable h3_ext.
   -U    Send_datagram 0 (off), 1 (on), 2(on + batch).