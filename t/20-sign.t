#!perl

use Test::More tests => 7;

BEGIN {
    use_ok( 'Net::Amazon::Signature::V4' ) || print "Bail out!\n";
}

use Net::Amazon::Signature::V4;
use HTTP::Request;

my $sha = '0123456789abcfdef0123456789abcfdef0123456789abcfdef0123456789abcfdef';
my $sig = Net::Amazon::Signature::V4->new(
    'AKIDEXAMPLE',
    'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
    'us-east-1',
    'service',
);
my $req = HTTP::Request->new( 'GET', 'http://hostname.example.net/something/cool' );
my $signed_req = $sig->sign( $req );

isa_ok($signed_req, "HTTP::Request");
isnt($signed_req->header("Date"), '', "Inserted missing Date header");
isnt($signed_req->header("x-amz-date"), '', "Inserted x-amz-date header");
isnt($signed_req->header("authorization"), '', "Inserted authorization header");
isnt($signed_req->header("X-Amz-Content-Sha256"), '', "Inserted x-amz-content-sha256 header");

my $req = HTTP::Request->new( 'GET', 'http://hostname.example.net/something/cool' );
$req->header("X-Amz-Content-Sha256",$sha);
my $signed_req = $sig->sign( $req );
is($signed_req->header("X-Amz-Content-Sha256"), $sha, "x-amz-content-sha256 is kept");
