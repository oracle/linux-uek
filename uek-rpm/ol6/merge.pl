#! /usr/bin/perl

my @args=@ARGV;
my %configvalues;
my @configoptions;
my $configcounter = 0;

# optionally print out the architecture as the first line of our output
my $arch = $args[2];
if (defined $arch) {
	print "# $arch\n";
}

# first, read the override file

open (FILE,"$args[0]") || die "Could not open $args[0]";
while (<FILE>) {
	my $str = $_;
	my $configname;

	if (/\# ([\w]+) is not set/) {
		$configname = $1;
	} elsif (/([\w]+)=/) {
		$configname = $1;
	}

	if (defined($configname) && !exists($configvalues{$configname})) {
		$configvalues{$configname} = $str;
		$configoptions[$configcounter] = $configname;
		$configcounter ++;
	}
};

# now, read and output the entire configfile, except for the overridden
# parts... for those the new value is printed.

open (FILE2,"$args[1]") || die "Could not open $args[1]";
while (<FILE2>) {
	my $configname;

	if (/\# ([\w]+) is not set/) {
		$configname = $1;
	} elsif (/([\w]+)=/) {
		$configname  = $1;
	}

	if (defined($configname) && exists($configvalues{$configname})) {
		print "$configvalues{$configname}";
		delete($configvalues{$configname});
	} else {
		print "$_";
	}
}

# now print the new values from the overridden configfile
my $counter = 0;

while ($counter < $configcounter) {
	my $configname = $configoptions[$counter];
	if (exists($configvalues{$configname})) {
		print "$configvalues{$configname}";
	}
	$counter++;
}

1;
