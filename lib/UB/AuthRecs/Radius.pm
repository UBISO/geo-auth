package UB::AuthRecs::Radius;
use base qw(UB::AuthRecs);
use NEXT;

# new ({raddbdsn, raddbuser, raddbpass})

sub new {
	my $this = shift;
	my $class = ref($this) || $this;
	my $self = {};
	bless $self, $class;

	
	$self->{p} = shift;

	$self->{p}->{debug} ||= 0;

	if (exists $self->{p}->{raddbdsn}) {
		$self->connect_authdb();
	}
	else {
		die "raddbdsn parameter is required";
	}
	
	return $self;
}

sub fetch_records {
	my $self = shift;
	my $sometimeago = shift;
	my $username = shift;
	$username ||= '';
	
	my $sql = qq{
select User_Name, Framed_Address as Local_Address, 
	Tunnel_Client_Endpoint as Remote_Address, radClient as NAS, 
       acct_session_start_time as Login_Time, acct_session_time as Duration
  from authHistory  
where acct_session_start_time >= $sometimeago };

	if ($username ne '') {
		$username = $self->{dbh}->quote($username);
		$sql .= qq{ AND User_Name like  } . $username;
	}
	
	$sql .= "order by User_Name, Login_Time;";

	# if Tunnel_Client_Endpoint is 'none' then it's a local (wireless) user
	# if it's not 'none' then it's a remote (vpn) user

	my $a = $self->{dbh}->selectall_arrayref($sql);
	return $a;	
}

sub connect_authdb {
	my $self = shift;
	
	$self->{dbh} = DBI->connect($self->{p}->{raddbdsn}, $self->{p}->{raddbuser}, $self->{p}->{raddbpass});
	
	if( !defined($self->{dbh}) ) {
	        die "ERROR: can't connect to raddb database: $DBI::errstr: $!";
	}
}

sub DESTROY {
	my $self = shift;
	$self->disconnect();
	$self->NEXT::DESTROY();
}

sub disconnect {
	my $self = shift;
	$self->{dbh}->disconnect if defined($self->{dbh});
	undef $self->{dbh};
}




1;