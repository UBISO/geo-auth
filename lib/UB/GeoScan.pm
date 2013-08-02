package UB::GeoScan;
use DBI;
use Data::Dumper;
use Net::LDAP;
use Carp qw(cluck);

# new( {
#       ldap_server =>
#       ldap_binddn =>
#       ldap_base   =>
#       ldap_filter =>
#       locationdb_dsn  =>
#       locationdb_user =>
#       locationdb_pass =>
#      }
#    )
   
sub new {
	my $this = shift;
	my $class = ref($this) || $this;
	my $self = {};
	bless $self, $class;

	$self->{p} = shift;

	return $self;
}

# lookupldap($username)

our %ldapcache;

sub lookupldap {
	my $self = shift;
	my $u = shift;
	return $ldapcache{$u} if exists $ldapcache{$u};
	
	my $ldap = new Net::LDAP($self->{p}->{ldap_server}) or die "$@";
	my $mesg = $ldap->bind($self->{p}->{ldap_binddn});
	my $lf = $self->{p}->{ldap_filter};
	$lf =~ s/\$username/$u/g;
	$mesg = $ldap->search(base => $self->{p}->{ldap_base},
			filter => $lf);
	$mesg->code && die $mesg->error;
	my $lde;
	foreach my $entry ($mesg->entries) { $lde = $entry; last; };
	$mesg = $ldap->unbind;
	$ldapcache{$u} = $lde;
	return $lde;
}

# lookuploc($ip, $dont_use_rtree)
# if dont_use_rtree is 1, then we will use a query
# that relies on typical indexes. the rtree query is 
# 10x faster. the original query is left in just for
# performance/curiousity measurements. 
#
# this assumes your sqlite module was built with rtree
# support. if this isnt the case, dont_user_rtree=1 is
# what you want and bad performance is what you'll get
# in return.

sub lookuploc {
        my $self = shift;
        my $_ip = shift;
        my $no_rtree = shift;


        $self->connect_locdb() if !defined($self->{sqlite});
        
        my $ub = $self->ub($_ip);
        return @$ub if defined($ub);
        return ('rfc1918', 'rfc1918', 'rfc1918', 0,0) if $self->rfc1918($_ip);
        
        my @ip = split(/\./, $_ip);
        my $ip = $self->ip2int($_ip);
        my $sql = "select longcc, region, city, latitude, longitude from ip2loc where oct1 = $ip[0] and $ip between ipstart and ipend";

        if (!defined($no_rtree) || ($no_rtree == 0)) {
        		# make signed int
                my $ip_i32 = $self->i32($ip);
                $sql = qq{
select longcc, region, city, latitude, longitude from ip2loc, ip2loc_rtree
 where ip2loc.rowid = ip2loc_rtree.id
   and x1 <= $ip_i32
   and x2 >= $ip_i32
                };
        }

        my $a = $self->{sqlite}->selectrow_arrayref($sql);
        
        if (!defined($a)) {
                warn "\n\nNo match for $_ip in lookuploc\n";
                return undef;
        }

        return ('bogon', 'bogon', 'bogon', 0, 0) if ($a->[0] eq "-");
        return @$a;
}


sub connect_locdb {
	my $self = shift;
	
	$self->{sqlite} = DBI->connect($self->{p}->{locdb_dsn}, $self->{p}->{locdb_user}, $self->{p}->{locdb_pass});
	die "cant connect to sqlite locdb " . DBI->errstr unless $self->{sqlite};
	
	if( !defined($self->{sqlite}) ) {
	        die "ERROR: can't connect to database: $DBI::errstr: $!";
	}
}


sub __DESTROY__ {
	my $self = shift;
	$self->disconnect();
}

sub disconnect {
	my $self = shift;
	$self->{sqlite}->disconnect if defined($self->{sqlite});
	undef $self->{sqlite};
}

sub distance {
  my $self = shift;
  my ($lat1, $lon1, $lat2, $lon2) = @_;
  my $c = 57.2958;

  3963.0 * $self->acos(sin($lat1/$c) * sin($lat2/$c) +
		cos($lat1/$c) * cos($lat2/$c) * cos($lon2/$c - $lon1/$c));
}

sub acos { my $self = shift; atan2(sqrt(abs(1 - $_[0] * $_[0])), $_[0]) };

sub rfc1918 {
	my $self = shift;
	my $ip = shift;
	if (!defined($ip)) {
		cluck("failed $ip");
	}
	return 1 if $ip =~ /^192\.168\./;
	return 1 if $ip =~ /^10\./;
	my @ip = split (/\./, $ip);
	return 1 if $ip[0] == 172 && $ip[1] > 15 && $ip[1] < 32;
}

sub ip2int {
	my $self = shift;
	my @ip = split(/\./, $_[0]);
	my $ip = $ip[0] << 24 | $ip[1] << 16 | $ip[2] << 8 | $ip[3];
	return $ip;
}

sub nm2int { my $self = shift; return eval("0b" . ("1" x ($_[0])) . ("0" x (32-$_[0]))); }

sub ub {
	my $self = shift;
	my $x = shift;
	my $ip = $self->ip2int($x);
	my @ub = (
		'67.20.192.0', '19',
		'67.99.160.0', '20',
		'128.205.0.0', '16',
		'205.232.16.0', '21'
	);

	for(my $i = 0 ; $i < $#ub ; $i += 2) {
#		printf "$x %x & %x = %x (%x)\n", $ip, nm2int($ub[$i+1]), ip2int($ub[$i]), ($ip & nm2int($ub[$i+1]));
		return ["UNITED STATES", "NEW YORK", "BUFFALO (UB)", 42.886447, -78.878369]
			if (($ip & $self->nm2int($ub[$i+1])) == $self->ip2int($ub[$i]));
	}
	return undef;
}

sub i32 {
		my $self = shift;
        my $i = shift;
        return unpack('i', pack('i', $i));
}

1;
