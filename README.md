# synerex_server
Synerex Server

## configure

copy file `config/private.test.key` to `config/private.key`　
and `config/public.test.key` to `config/public.key`, 
and editing content if you have a RSA key pair.

```shell script
cp config/private.test.key config/private.key
cp config/public.test.key config/public.key
```  

## build with docker

```
docker build ./ -t synerex_server
docker run --tty  --name synerex_server --rm -v $PWD:/go/src/github.com/synerex_server synerex_server
```
