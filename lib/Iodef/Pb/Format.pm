package Iodef::Pb::Format;
use base 'Class::Accessor';

use strict;
use warnings;

our $VERSION = '0.04';
$VERSION = eval $VERSION;

use Module::Pluggable require => 1, search_path => [__PACKAGE__];
use Try::Tiny;

__PACKAGE__->follow_best_practice();
__PACKAGE__->mk_accessors(qw(restriction_map group_map));

# have to do this to load the drivers
our @plugins = __PACKAGE__->plugins();

sub new {
    my $class = shift;
    my $args = shift;
     
    my $driver  = $args->{'format'} || 'Table';
    $driver     = __PACKAGE__.'::'.$driver;
   
    my $data;
    try {
        $driver = $driver->SUPER::new($args);
        $driver->init($args);
        $data   = $driver->write_out($args);
    } catch {
        my $err = shift;
        warn $err;
    };

    return $data;
}

sub init {
    my $self = shift;
    my $args = shift;
    
    $self->init_restriction_map($args);
    $self->init_group_map($args);
}

sub init_restriction_map {
    my $self = shift;
    my $args = shift;
    
    return unless($args->{'restriction_map'});
    
    my $map;
    foreach (@{$args->{'restriction_map'}}){
        $map->{$_->{'key'}} = $_->{'value'};
    }
    $self->set_restriction_map($map);
}

sub init_group_map {
    my $self = shift;
    my $args = shift;
    return unless($args->{'group_map'});
    
    my $map;
    foreach (@{$args->{'group_map'}}){
        $map->{$_->{'key'}} = $_->{'value'};
    }
    $self->set_group_map($map);
}

sub convert_restriction {
    my $self = shift;
    my $r = shift;
    return unless($r && $r =~ /^\d+$/);

    return 'private'        if($r == RestrictionType::restriction_type_private());
    return 'need-to-know'   if($r == RestrictionType::restriction_type_need_to_know());
    return 'public'         if($r == RestrictionType::restriction_type_public());
    return 'default'        if($r == RestrictionType::restriction_type_default());
}

sub to_keypair {
    my $self = shift;
    my $data = shift;
    
    my @array;
    
    # we do this in case we're handed an array of IODEF Documents
    if(ref($data) eq 'IODEFDocumentType'){
        $data = [$data];
    }
    foreach my $doc (@$data){
        next unless(ref($doc) eq 'IODEFDocumentType');
        foreach my $i (@{$doc->get_Incident()}){
            my $detecttime = $i->get_DetectTime();
            my $reporttime = $i->get_ReportTime();
        
            my $description = @{$i->get_Description}[0] ->get_content();

            my $id = $i->get_IncidentID->get_content();
        
            my $assessment = @{$i->get_Assessment()}[0];
        
            my $confidence = $assessment->get_Confidence->get_rating();
            if($confidence == ConfidenceType::ConfidenceRating::Confidence_rating_numeric()){
                $confidence = $assessment->get_Confidence->get_content() || 0;
                $confidence = sprintf("%.3f",$confidence) unless($confidence =~ /^\d+$/);
            }
            $assessment = @{$assessment->get_Impact}[0]->get_content->get_content();
        
            ## TODO -- restriction needs to be mapped down to event recursively where it exists in IODEF
            my $restriction = $i->get_restriction() || RestrictionType::restriction_type_private();
            my $purpose     = $i->get_purpose();
        
            my ($altid,$altid_restriction);
        
            if(my $x = $i->get_AlternativeID()){
                if(ref($x) eq 'ARRAY'){
                    $altid               = @{$x}[0];
                } else {
                    $altid               = $x;
                }
                $altid_restriction   = $altid->get_restriction();
                $altid               = @{$altid->get_IncidentID}[0]->get_content();
            }
            
            my $guid;
            if(my $iad = $i->get_AdditionalData()){
                foreach (@$iad){
                    next unless($_->get_meaning() =~ /^guid/);
                    $guid = $_->get_content();
                }
            }
            $restriction        = $self->convert_restriction($restriction);
            $altid_restriction   = $self->convert_restriction($altid_restriction);
            if(my $map = $self->get_restriction_map()){
                if(my $r = $map->{$restriction}){
                    $restriction = $r;
                }
                if($altid_restriction && (my $r = $map->{$altid_restriction})){
                    $altid_restriction = $r;
                }
            }

            if($self->get_group_map && $self->get_group_map->{$guid}){
                $guid = $self->get_group_map->{$guid};
            }
            
            my $hash = {
                id          => $id,
                guid        => $guid,
                description => $description,
                detecttime  => $detecttime,
                reporttime  => $reporttime,
                confidence  => $confidence,
                assessment  => $assessment,
                restriction => $restriction,
                purpose     => $purpose,
                alternativeid               => $altid,
                alternativeid_restriction   => $altid_restriction,
            };
            if(my $ad = $i->get_AdditionalData()){
                foreach my $a (@$ad){
                    next unless($a->get_meaning() eq 'hash');
                    $hash->{'hash'}         = $a->get_content();
                    push(@array,$hash);
                }
            }
            if($i->get_EventData()){
                foreach my $e (@{$i->get_EventData()}){
                    my @flows = (ref($e->get_Flow()) eq 'ARRAY') ? @{$e->get_Flow()} : $e->get_Flow();
                    foreach my $f (@flows){
                        my @systems = (ref($f->get_System()) eq 'ARRAY') ? @{$f->get_System()} : $f->get_System();
                        foreach my $s (@systems){
                            my $asn;
                            my $ad = $s->get_AdditionalData();
                            if($ad){
                                foreach (@$ad){
                                    $asn = $_->get_content() if($_->get_meaning() eq 'asn');
                                }
                            }
                            
                            my @nodes = (ref($s->get_Node()) eq 'ARRAY') ? @{$s->get_Node()} : $s->get_Node();
                            my $service = $s->get_Service();
                            foreach my $n (@nodes){
                                my $addresses = $n->get_Address();
                                $addresses = [$addresses] if(ref($addresses) eq 'AddressType');
                                foreach my $a (@$addresses){
                                    $hash->{'address'}     = $a->get_content();
                                    $hash->{'restriction'} = $restriction;
                                    $hash->{'asn'}         = $asn;  
                                    
                                    if($service){
                                        my ($portlist,$protocol);
                                        foreach my $srv (@$service){
                                            $hash->{'portlist'} = $srv->get_Portlist();
                                            $hash->{'protocol'} = $srv->get_ip_protocol();
                                            push(@array,$hash);
                                        }
                                    } else {
                                        push(@array,$hash);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return(\@array); 
}

1;
  
__END__

=head1 NAME

Iodef::Pb - Perl extension for formatting an array of IODEFDocumentType (IODEF protocol buffer objects) messages into things like tab-delmited tables, csv and snort rules

=head1 SYNOPSIS
    
  use Iodef::Pb::Simple;
  use Iodef::Pb::Format;

  my $i = Iodef::Pb::Simple->new({
    address         => '1.2.3.4',
    confidence      => 50,
    severity        => 'high',
    restriction     => 'need-to-know',
    contact         => 'Wes Young',
    assessment      => 'botnet',
    description     => 'spyeye',
    alternativeid   => 'example2.com',
    id              => '1234',
    portlist        => '443,8080',
    protocol        => 'tcp',
    asn             => '1234',
  });

  my $ret = Iodef::Pb::Format->new({
    driver  => 'Table', # or 'Snort'
    data    => $i,
  });

  warn $ret;

=head1 DESCRIPTION

This is a helper library for Iodef::Pb. It'll take a single (or array of) IODEFDocumentType messages and transform them to a number of different outputs (Table, Snort, etc).

=head2 EXPORT

None by default. Object Oriented.

=head1 SEE ALSO

 http://github.com/collectiveintel/iodef-pb-simple-perl
 http://collectiveintel.net

=head1 AUTHOR

Wes Young, E<lt>wes@barely3am.comE<gt>

=head1 COPYRIGHT AND LICENSE

  Copyright (C) 2012 by Wes Young <claimid.com/wesyoung>
  Copyright (C) 2012 the REN-ISAC <ren-isac.net>
  Copyright (C) 2012 the trustee's of Indiana University <iu.edu>

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.1 or,
at your option, any later version of Perl 5 you may have available.


=cut
