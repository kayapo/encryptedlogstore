#!/usr/bin/perl -w
use strict;
use Crypt::OpenSSL::RSA;
use Getopt::Long;
use Time::HiRes qw( gettimeofday );

# Fuggosegek:
#    libcrypt-openssl-random-perl
#    libcrypt-openssl-rsa-perl
#    libcrypt-openssl-bignum-perl
#
# Kulcs generalas:
#   /usr/bin/openssl genrsa -aes256 -out private.pem 2048
#   /usr/bin/openssl rsa -in private.pem -out public.pem -outform PEM -pubout

my $sec;
my $microsec;
my $line;

my $dateFormatedLogFiles;
my $logDir;
my $logFile;
my $help;
my $keyFile;

# A parancssori kapcsolok elolvasasa
my $options = GetOptions(
                         "d|date-formated-logfiles" => \$dateFormatedLogFiles,
                         "l|logdir=s" => \$logDir,
                         "f|log-file=s" => \$logFile,
                         "h|?|help" => \$help,
                         "k|keyfile=s" => \$keyFile
                         );

# Kiirja a help -et, ha a -h -? --help
# kapcsolo meg van adva
if ( defined $help ) {
    &help;
    exit 0;
}

# Kilep ha a -l --logdir nincs megadva
if ( ! defined $logDir ) {
    print STDERR "Logdir is not set!\n";
    exit 1;
}

# Kilep ha a -k --keyfile nincs megadva
if ( ! defined $keyFile ) {
    print STDERR "Keyfile is not set!\n";
    exit 1;
}

# Kilep, ha -d --date-formated-logfiles vagy a -f --log-file
# nincs megadva
unless ( defined $logFile || defined $dateFormatedLogFiles ) {
    print STDERR "--log-file or --date-formated-logfiles required!\n";
    exit 1;
}

# Betolti a kulcsfilet
open KEYFILE,"<",$keyFile;
my @keyLines = <KEYFILE>;
$keyFile = join "", @keyLines;
close KEYFILE;
my $rsa_pub = Crypt::OpenSSL::RSA->new_public_key($keyFile);

# Var a logsorokra
while ( my $line = <> ) {
    last if $line eq '';
    ( $sec, $microsec ) = gettimeofday;
    $line = sprintf "%d.%0.6d\t$line", $sec, $microsec, $line;

    my $ciphertext = $rsa_pub->encrypt(\$line);
    open LOG,">>","$logDir/$logFile" || die "I don't open file in $logDir/$logFile\n";
    print LOG $ciphertext;
    close LOG;
}

sub help {
print<<HELP;
Usage: $0 -k -l -d
    -d  --date-formated-logfiles
    -l  --logdir
    -f  --log-file
    -k  --keyfile
    -h  -?  --help
HELP
}