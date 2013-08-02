package UB::AuthRecs;

# new ({debug=>...})

sub new {
	my $this = shift;
	my $class = ref($this) || $this;
	my $self = {};
	bless $self, $class;

	
	$self->{p} = shift;

	$self->{p}->{debug} ||= 0;

	return $self;
}


sub username {
	my $self = shift;
    my $u = shift;
    $u =~ s/\@.*$//g;   # strip @domain suffixes
    $u =~ s/\s+\\\\//g; # strip AD\\ style realms
    return $u;
}

sub client {
	my $self = shift;
    my $c = shift;
    my @a = split(/\[/, $c);

    $a[1] =~ s/\]//g;
    return ($a[0], $a[1]);
}

sub convtime_to_ts {
	my $self = shift;
	my $t = shift;
	# 2012-10-26T07:56:11.
	if ($t =~ /^(\d+)-(\d+)-(\d+)T(\d\d):(\d\d):(\d\d)/) {
        use Date::Manip;
		my $unixtime = UnixDate($t, "%s");
		return $unixtime;
	}
	die 'cant convert time to ts (expecting /^(\d+)-(\d+)-(\d+)T(\d\d:\d\d:\d\d)/): '. $t;
}

sub convtime_for_cef {
	my $self = shift;
    my $t = shift;
    if ($t =~ /^(\d+)-(\d+)-(\d+)T(\d\d:\d\d:\d\d)/) {
		return ('ERR', 'JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC')[$2] ." $3 $1 $4";
    }
    return $t;
}

sub cef {
	my $self = shift;
    my ($t, $u, $cn, $cip, $h) = (convtime_for_cef(shift), username(shift), client(shift), shift);

    my $cef = "CEF:0|Postfix|Postfix|2|101|SMTP Authentication|2|act=Permit app=SMTP dvchost=$h proto=TCP";
    $cef .= " categorySignificance=/Informational categoryBehavior=/Authentication/Verify categoryOutcome=/Success categoryObject=/Host/Application/Service categoryDeviceGroup=/Application ";
    $cef .= " src=$cip ";
    $cef .= " shost=$cn " if $cn ne "unknown";
    $cef .= " suser=$u ";
    $cef .= " rt=$t start=$t msg=Successful SMTP authentication";

    return $cef;
}

1;
