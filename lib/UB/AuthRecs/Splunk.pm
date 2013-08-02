package UB::AuthRecs::Splunk;
use base qw(UB::AuthRecs);
use WWW::Splunk;
use NEXT;

# new ({splunkserver, splunkuser, splunkpass})

sub new {
	my $this = shift;
	my $class = ref($this) || $this;
	my $self = {};
	bless $self, $class;

	
	$self->{p} = shift;

	$self->{p}->{debug} ||= 0;

	if (exists $self->{p}->{splunkserver}) {
		if ($self->{p}->{splunkserver} =~ /(.*):(\d*)/) {
			$self->{p}->{splunkport}   = $2;
			$self->{p}->{splunkserver} = $1;
		} 
		else {
			$self->{p}->{splunkport} = 80;
		}
	
		$self->{splunk} = new WWW::Splunk ({
          host       => $self->{p}->{splunkserver},
          port       => $self->{p}->{splunkport},
          login      => $self->{p}->{username},
          password   => $self->{p}->{password},
          unsafe_ssl => 1,
	      debug      => $self->{p}->{debug}
  		});

		die unless $self->{splunk};
	}
	
	return $self;
}

sub DESTROY {
	my $self = shift;
	$self->disconnect();
	$self->NEXT::DESTROY();
}

sub disconnect {
	my $self = shift;
	undef $self->{splunk};
}

sub fetch_smtp_logins_from_splunk {
	my $self = shift;
	my $hours_ago = shift;
	die "splunk_search(hours_ago) parameter must be a positive integer and not \"$hours_ago\""
		unless ($hours_ago =~ /^\d+$/);
	
	my $user = shift;
	$user ||= "*";
	
	my $earliest_time = "-${hours_ago}h";
	
	my $srch =  "search sasl_method=LOGIN client=* sasl_username=$user";
	
	if ($self->{p}->{debug} > 0) {
		print "Splunk search is: $srch\n";
	}
	
	my $sid = $self->{splunk}->start_search ( 
					{   search => $srch,
					    earliest_time => $earliest_time,
					    #earliest_time => '2011-07-12 00:00',
					    #latest_time => '2011-07-12 12:00',
					    #time_format => '%Y-%m-%d %H:%M'
					}
					  );
	
	$self->{splunk}->poll_search ($sid);
		
	my $rv = { 'time' => [], 'ts' => [], 'username' => [], 'remotehost' => [], 'remoteaddr' => [], 'smtpserver' => [] };
	
	until ($self->{splunk}->results_read ($sid)) {
	    my @res = $self->{splunk}->search_results($sid);
	    foreach my $r (@res) {
			if (exists $r->{sasl_method}) {
			
				my $rh; my $ra;
				if ($r->{client} =~ /(\S+)\[(\S+)\]/) {
					$rh = $1;
					$ra = $2;
				}
				else {
					die 'cant parse client (expecting /\S+[\S+]/): ' . $r->{client};
				}
				
				push @{$rv->{'time'}}, $r->{_time};
				push @{$rv->{'ts'}}, $self->convtime_to_ts($r->{_time});
				push @{$rv->{'username'}}, $self->username($r->{sasl_username});
				push @{$rv->{'remotehost'}}, $rh;
				push @{$rv->{'remoteaddr'}}, $ra;
				push @{$rv->{'smtpserver'}}, $r->{host};
			
				printf("time %s (%d) username %s remotehost %s remoteaddr %s smtpserver %s\n", 
					  $r->{_time},
					  $self->convtime_to_ts($r->{_time}),
				      $self->username($r->{sasl_username}),
				      $rh, $ra,
				      $r->{host}
				      ) if $self->{p}->{debug} > 0;
			}
	    }
	}
	
	return $rv;
}




1;