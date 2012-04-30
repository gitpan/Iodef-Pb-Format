package Iodef::Pb::Format::Table;
use base 'Iodef::Pb::Format';

use strict;
use warnings;

use Text::Table;

sub write_out {
    my $self = shift;
    my $args = shift;
    
    my $array = $self->by_address($args->{'data'});
    
    my @cols;
    push(@cols,(
        'restriction',
        'guid',
        'assessment',
        'description',
        'confidence',
        'detecttime',
        'reporttime',
    ));
    
    my $test = @{$array}[0];

    if($test->{'address'}){
        push(@cols,'address');
    }
    if($test->{'protocol'}){
        push(@cols,'protocol');
    }
    if($test->{'portlist'}){
        push(@cols,'portlist');
    }
    if($test->{'rdata'}){
        push(@cols,'rdata');
    }
    if($test->{'asn'}){
        push(@cols,'asn');
    }
    
    push(@cols,(
        'alternativeid_restriction',
        'alternativeid',
    ));
    

    my @header = map { $_, { is_sep => 1, title => '|' } } @cols;
    pop(@header);
    my $table = Text::Table->new(@header);
    
    foreach my $e (@$array){
        $table->load([ map { $e->{$_} } @cols]);
    }
    return $table;
}

1;