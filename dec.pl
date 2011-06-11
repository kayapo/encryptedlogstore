#!/usr/bin/perl -w
use strict;
use Crypt::OpenSSL::RSA;
use Getopt::Long;

my $keyFile;
my $inFile;
my $encData;
my $n;
my $plainLine;

my $options = GetOptions(
                         "k|keyfile=s" => \$keyFile,
                         "f|infile=s" => \$inFile
                         );

unless ( defined $keyFile && defined $inFile ) {
    print STDERR "-k --keyfile and -f --infile is required!\n";
    exit 1;
}

# Betolti a kulcsfilet
open KEYFILE,"<",$keyFile || die "I don't open key file:\n\t$!\n";
my @keyLines = <KEYFILE>;
$keyFile = join "", @keyLines;
close KEYFILE;
my $rsa_priv = Crypt::OpenSSL::RSA->new_private_key($keyFile) || die "$!\n";

open ENCFILE, "<", $inFile || die "I don't open input file:\n\t$!\n";
while ( ($n = read ENCFILE, $encData, 256) != 0 ) {
    my $last = chop $encData;
    $plainLine = $rsa_priv->decrypt($encData);
    print $plainLine;
}
