use strict;
use warnings FATAL => 'all';

use Apache::Test;
use Apache::TestUtil;
use Apache::TestModPerimeterX;

plan tests => 1;

my $cookie_baker = Apache::TestModPerimeterX->new;
my $cookie = $cookie_baker->cookie_baker;
print "cookie: $cookie\n";
#print "what is this: $cookie_baker\n";

#my $cookie = $test_utils->bake_cookie()
#print "$cookie\n";
ok 1;
