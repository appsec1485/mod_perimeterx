# Testing

## Docker

### Build Docker
```bash
docker build -t mod_perimeterx-test -f Dockerfile-test .
```
### Run tests on Docker

```bash
docker run -e APP_ID=${APP_ID} -e AUTH_TOKEN=${AUTH_TOKEN} mod_perimeterx-test
```

Replace `${APP_ID}` and `${AUTH_TOKEN}` with application id and it's auth token:

```bash
docker run mod_perimeterx-test -e APP_ID=PX1234 AUTH_TOKEN=my_app_secret
```

## Locally (Ubuntu) 

### Installing Dependencies

#### cpanminus

```bash
apt-get install cpanminus
```

#### mod_perimeterx

    git clone https://github.com/PerimeterX/mod_perimeterx.git
    cd mod_perimeterx

#### Apache 2.4

    sudo apt-get install --assume-yes apache2-mpm-prefork apache2-utils apache2-dev

### Perl dependencies

    cpanm --installdeps --notest .

### Test scaffolding

    perl Makefile.PL -configure -httpd_conf t/setup/apache2.conf -src_dir /usr/lib/apache2/modules
    
> Note: for now you should manually replace the placeholders for APP\_ID and AUTH\_TOKEN in `t/conf/extra.conf` file before running the tests.

### Run tests

    ./t/TEST -v
