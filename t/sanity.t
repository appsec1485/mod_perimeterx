use strict;
use warnings FATAL => 'all';

use Apache::Test;
use Apache::TestRequest qw(GET);
use Apache::ModPerimeterXTestUtils;

plan tests => 1;

my $time = ( time() + 360 ) * 1000;

my $cookie = bake_cookie(
	"1.2.3.4",
	"libwww-perl/0.00",
	"20",
	"57ecdc10-0e97-11e6-80b6-095df820282c",
	"vid",
	$time
);

my $res = GET '/index.html', 'real-ip' => '1.2.3.4', 'Cookie' => $cookie; 
ok $res->code == 200
