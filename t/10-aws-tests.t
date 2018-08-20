#!perl

use warnings;
use strict;
use Net::Amazon::Signature::V4;
use File::Slurper 'read_text';
use HTTP::Request;
use Test::More;
use File::Find;

my $testsuite_dir = 't/aws4_testsuite_20150830';
my @test_names = ();

sub crate_test_names;

File::Find::find({wanted => \&crate_test_names}, $testsuite_dir);

# only .req is supplied for test "get-header-value-multiline"; why?

plan tests =>  1+4*@test_names;

my $sig = Net::Amazon::Signature::V4->new(
	'AKIDEXAMPLE',
	'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
	'us-east-1',
	'service',
);

ok( -d $testsuite_dir, 'testsuite directory existence' );
$Net::Amazon::Signature::V4::ADD_CONTENT_SHA256 = 0;

for my $test_name ( @test_names ) {

	ok( -f "$testsuite_dir/$test_name.req", "$test_name.req existence" );
	my $reqtext = read_text( "$testsuite_dir/$test_name.req" );
	my $req = HTTP::Request->parse( $reqtext);
	# Fix HTTP::Request bug when parsing requests with spaces in uri path
	$req->uri($1) if ($reqtext =~ /^[A-Z]+ (.*) HTTP\b/s);
	#diag("$test_name creq");
	my $creq = $sig->_canonical_request( $req );
	if ( ! string_fits_file( $creq, "$testsuite_dir/$test_name.creq" ) ) {
		fail( "canonical request mismatch, string-to-sign can't pass" );
		fail( "canonical request mismatch, authorization can't pass" );
		next;
	}

	#diag("$test_name sts");
	my $sts = $sig->_string_to_sign( $req );
	if ( ! string_fits_file( $sts, "$testsuite_dir/$test_name.sts" ) ) {
		fail( "string-to-sign request mismatch, authorization can't pass" );
		next;
	}

	#diag("$test_name authz");
	my $authz = $sig->_authorization( $req );
	$authz=~ s/,Sign/, Sign/g;
	string_fits_file( $authz, "$testsuite_dir/$test_name.authz" );
}

sub string_fits_file {
	my ( $str, $expected_path ) = @_;
	my $expected_str = read_text( $expected_path );
	$expected_str =~ s/\r\n/\n/g;
	is( $str, $expected_str, $expected_path );
	return $str eq $expected_str;
}
sub crate_test_names {
    $File::Find::name =~ /^$testsuite_dir\/(.*)\.req\z/s && push (@test_names,$1);
}

