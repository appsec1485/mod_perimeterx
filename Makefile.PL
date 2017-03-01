require 5.6.1;

use ExtUtils::MakeMaker;

use Apache::TestMM qw(test clean); #enable 'make test'

use lib qw(../blib/lib lib);

my %require => {
    "Apache::Test" => "",
};

my @scripts = qw(t/TEST);
print STDOUT %scripts;

Apache::TestMM::filter_args();
Apache::TestMM::generate_script('t/TEST');

WriteMakefile(
    NAME => 'Apache::Test_mod_perimeterx',
    #VERSION_FROM => 'lib/Test/ModPerimeterX.pm',
    PREREQ_PM => \%require,
    clean => {
        FILES => "@{ clean_files() }",
    },
    ($] >= 5.005 ?
        (
            #ABSTRACT_FROM => 'lib/Test/ModPerimeterX.pm',
            AUTHOR => 'Aviad Shikloshi <aviad (at) perimeterx.com>',
        ) : ()
    ),
);

sub clean_files {
    return [@scripts];
}

