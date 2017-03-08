use strict;
use warnings FATAL => 'all';

use Apache::Test;
use Apache::TestRequest qw(GET);
use Apache::ModPerimeterXTestUtils;

plan tests => 1;

my $time = ( time() + 360 ) * 1000;

my $cookie = valid_good_cookie;

my $res = GET '/index.html', 'real-ip' => '1.2.3.4', 'Cookie' => $cookie;
ok $res->code == 200
