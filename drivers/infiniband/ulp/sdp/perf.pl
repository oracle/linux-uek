#!/usr/bin/perl

use strict;

sub average {
	@_ == 1 or die ('Sub usage: $average = average(\@array);');
	my ($array_ref) = @_;
	my $sum;
	my $count = scalar @$array_ref;
	foreach (@$array_ref) { $sum += $_; }
	return 0 if !$count;
	return $sum / $count;
}

sub median {
	@_ == 1 or die ('Sub usage: $median = median(\@array);');
	my ($array_ref) = @_;
	my $count = scalar @$array_ref;

	# Sort a COPY of the array, leaving the original untouched
	my @array = sort { $a <=> $b } @$array_ref;
	if ($count % 2) {
		return $array[int($count/2)];
	} else {
		return ($array[$count/2] + $array[$count/2 - 1]) / 2;
	}
}

open FD, "</proc/net/sdpprf" || die "Couldn't find proc file";

my %create_time;
my @skb_send_till_posted;
my @skb_send_interval;
my @skb_post_interval;
my $last_send_time = -1;
my $last_post_time = -1;

while (my $line = <FD>) {
	if ($line =~ /^([0-9]*).*\[([0-9 .]*)\] Created.*skb: ([0-9a-f]*)/) {
		my $idx = $1;
		my $time = $2;
		my $skb = $3;
		$create_time{$skb} = $time;
		if ($last_send_time > -1) {
			my $delta = $time - $last_send_time;
			$delta = int($delta * 1000000);
			push @skb_send_interval, $delta;
			print "skb_send_interval: $idx $skb - $delta\n";
		}
		$last_send_time = $time;
#		print "Start: $time - $skb\n";
	} elsif ($line =~ /^([0-9]*).*\[([0-9 .]*)\] post_send mid = SDP_MID_DATA.*skb: ([0-9a-f]*)/) {
		my $idx = $1;
		my $time = $2;
		my $skb = $3;
		if ($last_post_time > -1) {
			my $delta = $time - $last_post_time;
			$delta = int($delta * 1000000);
			push @skb_post_interval, $delta;
			print "skb_post_interval: $idx $skb - $delta\n";
		}
		$last_post_time = $time;
		if ($create_time{$skb}) {
			my $delta = $time - $create_time{$skb};
			$delta = int($delta * 1000000);
#			print "create..send $skb $time..$create_time{$skb}: $delta usec\n";
			push @skb_send_till_posted, $delta;
		}
	}
}

print "skb send .. posted:\n";
print "  median : " . median(\@skb_send_till_posted) . "\n";
print "  average: " . average(\@skb_send_till_posted) . "\n";

print "skb send interval:\n";
print "  median : " . median(\@skb_send_interval) . "\n";
print "  average: " . average(\@skb_send_interval) . "\n";

print "skb post interval:\n";
print "  median : " . median(\@skb_post_interval) . "\n";
print "  average: " . average(\@skb_post_interval) . "\n";

close FD;
