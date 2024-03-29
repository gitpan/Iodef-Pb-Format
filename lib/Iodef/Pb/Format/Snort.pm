package Iodef::Pb::Format::Snort;
use base 'Iodef::Pb::Format';

use Snort::Rule;
use Regexp::Common qw/net/;
use Parse::Range qw(parse_range);

sub write_out {
    my $self = shift;
    my $args = shift;
    
    my $config = $args->{'config'};
    
    my $array = $self->SUPER::to_keypair($args->{'data'});
    
    return '' unless(exists(@{$array}[0]->{'address'}));

    $config = $config->{'config'};
    
    # allow override of snort rule params
    my $tag         = confor($config, 'snort_tag', undef);
    my $pri         = confor($config, 'snort_priority', undef);
    my $sid         = confor($config, 'snort_startsid', 1);
    my $thresh      = confor($config, 'snort_threshold', 'type limit,track by_src,count 1,seconds 3600');
    my $classtype   = confor($config, 'snort_classtype', undef);
    my $srcnet      = confor($config, 'snort_srcnet', 'any');
    my $srcport     = confor($config, 'snort_srcport', 'any');
    my $msg_prefix  = confor($config, 'snort_msg_prefix','');
    
    my $rules = '';
    foreach (@$array){
        next unless($_->{'address'});
        if(exists($_->{'rdata'})){
            $_->{'portlist'} = 53;
        }
        my $portlist = ($_->{'portlist'}) ? $_->{'portlist'} : 'any';

        my $priority = 1;
        for(lc($_->{'severity'})){
            $priority = 5 if(/medium/);
            $priority = 9 if(/high/);
        }

        my $dstnet      = 'any';
        my $dstport     = 'any';
        my $urlhost     = undef;
        my $dnsdomain   = undef;
        my ($urlport, $urlfile);

        if (isipv4($_->{'address'})) {
            $dstnet = $_->{'address'};
            $dstport = $portlist;
        }
        elsif (isdomain($_->{'address'})) {
            #$_->{'protocol'} = 17 unless($_->{'protocol'});
            # it's not clear if this should be strictly 'alert udp ...' or 'alert ip ...'
            # for now this is safe till we have more data on the functionality.
            
            $_->{'protocol'} = 17;
            
            $dstport = 53;
            $dstnet = 'any';
            $dnsdomain = $_->{'address'};
        } else {
            ($urlhost, $urlport, $urlfile) = ishttpurl($_->{'address'});
            if (defined($urlhost)) {
                my $urlisip = isipv4($urlhost);
                $_->{'protocol'} = 6; # TCP by definition
                $dstnet = ($urlisip ? $urlhost : 'any'); # $EXTERNAL_NET?
                $dstport = $urlport || '$HTTP_PORTS';
            }
            else {
                $rules .= "### sorry. not sure what to do with address: " . $_->{'address'} . " so i'm skipping this one.\n\n";
                next;
            }
        }
        my $r = Snort::Rule->new(
            -action => 'alert',
            -proto  => translate_proto($_->{'protocol'}),
            -src    => $srcnet,
            -sport  => join(',', (($srcport =~ /^[,\-\d]+$/) ? parse_range($srcport) : $srcport)),
            -dst    => $dstnet,
            -dport  => join(',', (($dstport =~ /^[,\-\d]+$/) ? parse_range($dstport) : $dstport)),
            -dir    => '->',
        );

        my $reference = make_snort_ref($_->{'alternativeid'});
    
        $r->opts('msg',$msg_prefix . $_->{'restriction'}.' - '.$_->{'assessment'}.' '.$_->{'description'});
        $r->opts('threshold', $thresh) if $thresh;
        $r->opts('tag', $tag) if $tag;
        $r->opts('classtype', $classtype) if $classtype;
        $r->opts('sid', $sid++);
        $r->opts('reference',$reference) if($reference);
        $r->opts('priority', $pri || $priority);

        #alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (Msg: "Mal_URI
        #www.badsite.com/malware.pl"; flow: to_server, established;
        #content:"Host|3A| www.basesite.com"; nocase;
        #content:"/malware.pl"; http_uri; nocase; sid:23424234;)
        if ($urlhost) {
            $rules .= "# $urlhost    [urlhost rule]\n";
            $r->opts('flow', 'to_server');
            if (!isipv4($urlhost)) {
                $r->opts('content', 'Host|3A| ' . escape_content($urlhost));
                $r->opts('http_header');
                $r->opts('nocase');
            }
            if ($urlfile) {
                $r->opts('content', escape_content($urlfile));
                $r->opts('http_uri');
                $r->opts('nocase');
            }
        } 
        elsif ($dnsdomain) {
            $rules .= "# $dnsdomain    [domain-only (dns) rule]\n";
            # alert udp !$DNS_SERVERS any -> any 53 ( msg:"RESTRICTED - botnet domain unknown"; sid:1; content:"|03|foo|03|com"; )
            $r->opts('content', content_as_dns_query($dnsdomain)); # dont have to escape bc we passed isdomain() test above
            $r->opts('nocase');
        } 
        else {
            $rules .= "# $dstnet [ip address only / not url / not domain rule]\n"
        }

        $rules .= $r->string()."\n\n";
    }
    return $rules;
}

sub content_as_dns_query {
    my $d = shift;
    return '' unless $d;
    return join('', map { sprintf("|%2.2x|%s", length($_), $_) } split('\.', $d));
}

sub isipv4 {
    my ($i, $m) = (shift, 32);
    ($i, $m) = split('/', $i) if ($i =~ /\//);
    return 1 if ( 
        ($i =~ /^0*([1-9]?\d|1\d\d|2[0-4]\d|25[0-5])(\.0*([1-9]?\d|1\d\d|2[0-4]\d|25[0-5])){3}$/) &&
        ($m > 0 && $m < 33)
        );
    return 0;
}

sub translate_proto {
    my $protonum = shift;   
    my $protos = { 6 => 'tcp', 17 => 'udp', 1 => 'icmp' }; # snort only supports these, default is 'ip'
    return $protos->{$protonum} if (defined($protonum) && exists($protos->{$protonum}));
    return 'ip';
}

sub confor {
    my $conf = shift;
    my $name = shift;
    my $def = shift;

    # handle
    # snort_foo = 1,2,3
    # snort_foo = "1,2,3"

    if (exists($conf->{$name}) && defined($conf->{$name})) {
        return ref($conf->{$name} eq "ARRAY") ? join(', ', @{$conf->{$name}}) : $conf->{$name};
    }
    return $def;
}

sub isdomain {
    my $x = shift;
    if ($x =~ /^[0-9a-z\.\-]+\.[a-z]{2,6}$/i) {
        return 1;
    } 
    return 0;
}

sub ishttpurl {
    my $x = shift;

    return (undef, undef, undef) unless $x;

    # it only makes sense to try to look for http: urls
    # https will be encrypted, ftp doesnt contain header fields to trigger on, etc

    if ($x =~ /http:\/\/([^\/]+)[\/]{0,1}(.*)/) {
        my ($h, $p) = split(':', $1);
        my $d = ($2 ? '/'.$2 : '');
        return ($h, $p, $d);
    }
    return (undef, undef, undef); 
}

sub make_snort_ref {
    my $r = shift;
    return undef unless defined($r);
    if ($r =~ /(https?):\/\/(.*)/) {
        return "url," . $2 if ($1 eq "http");
        return "urlssl," . $2;
    }
    return 'url,' . $r if($r =~ /[a-z0-9-.]+\.[a-z]{2,6}(\/)?/);
    return undef;
}

# http://manual.snort.org/node32.html#SECTION00451000000000000000
#Note:  
#Also note that the following characters must be escaped inside a content rule:
#
#    ; \ "
    
sub escape_content {
    my $x = shift;
    $x =~ s/\\/\\\\/gi;
    $x =~ s/;/\\;/gi;
    $x =~ s/\"/\\"/gi;
    return $x;
}
1;
