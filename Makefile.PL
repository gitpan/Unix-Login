use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'Unix::Login',
    'VERSION_FROM' => 'Login.pm', # finds $VERSION
);
