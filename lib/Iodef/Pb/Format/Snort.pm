package Iodef::Pb::Format::Snort;
use base 'Iodef::Pb::Format';

use Snort::Rule;
use Regexp::Common qw/net/;

sub write_out {
    my $self = shift;
    my $args = shift;
    
    my $config = $args->{'config'};
    
    my $array = $self->SUPER::to_keypair($args->{'data'});
    
    return '' unless(exists(@{$array}[0]->{'address'}));

    $config = $config->{'config'};
    my $sid = ($config->{'snort_startsid'}) ? $config->{'snort_startsid'} : 1;
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

        my $r = Snort::Rule->new(
            -action => 'alert',
            -proto  => 'ip',
            -src    => 'any',
            -sport  => 'any',
            -dst    => $_->{'address'},
            -dport  => $portlist,
            -dir    => '->',
        );
        $r->opts('msg',$_->{'restriction'}.' - '.$_->{'assessment'}.' '.$_->{'description'});
        $r->opts('threshold','type limit,track by_src,count 1,seconds 3600');
        $r->opts('sid',$sid++);
        $r->opts('reference',$_->{'alternativeid'}) if($_->{'alternativeid'});
        $r->opts('priority',$priority);
        $rules .= $r->string()."\n";
    }
    return $rules;
}
1;
