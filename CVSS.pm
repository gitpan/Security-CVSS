package Security::CVSS;

use 5.008;
use strict;
use warnings;

use Module::Check_Args;
use Carp qw( croak );

our $VERSION = '0.01';

our %BASE_PARAMS =
            (
                AccessVector          => {'remote'   => 1,   'local'           => 0.7},
                AccessComplexity      => {'low'      => 1,   'high'            => 0.8},
                Authentication        => {'required' => 0.6, 'not-required'    => 1},
                ConfidentialityImpact => {'none'     => 0,   'partial'         => 0.7, 'complete'  => 1},
                IntegrityImpact       => {'none'     => 0,   'partial'         => 0.7, 'complete'  => 1},
                AvailabilityImpact    => {'none'     => 0,   'partial'         => 0.7, 'complete'  => 1},
                ImpactBias            => {'normal'   => 1,   'confidentiality' => 1,   'integrity' => 1, 'availability' => 1}
            );

our %TEMPORAL_PARAMS =
            (
                Exploitability   => {'unproven'     => 0.85, 'proof-of-concept' => 0.9,  'functional' => 0.95, 'high'        => 1 },
                RemediationLevel => {'official-fix' => 0.87, 'temporary-fix'    => 0.90, 'workaround' => 0.95, 'unavailable' => 1.00 },
                ReportConfidence => {'unconfirmed'  => 0.9,  'uncorroborated'   => 0.95, 'confirmed'  => 1.00}
            );

our %ENVIRONMENTAL_PARAMS =
            (
                CollateralDamagePotential => {'none' => 0, 'low' => 0.1,  'medium' => 0.3,  'high' => 0.5},
                TargetDistribution        => {'none' => 0, 'low' => 0.25, 'medium' => 0.75, 'high' => 1}
            );

our %ALL_PARAMS = (%BASE_PARAMS, %TEMPORAL_PARAMS, %ENVIRONMENTAL_PARAMS);

# Create accessors for all parameters
foreach my $Accessor (keys %ALL_PARAMS)
{
    no strict 'refs';
    *{"Security::CVSS::$Accessor"} = sub
        {
            exact_argcount(2);
            my $self = shift;
            $self->_ValidateParam($Accessor, @_);
        };
}

sub new
{
    range_argcount(1, 2);
    my $class  = shift;
    my $Params = shift;

    my $self   = bless({}, $class);

    if (defined($Params))
    {   $self->UpdateFromHash($Params); }

    return $self;
}

sub UpdateFromHash
{
    exact_argcount(2);
    my ($self, $Params) = @_;

    if (ref($Params) ne 'HASH')
    {   croak 'Parameter must be a hash reference'; }

    foreach my $Param (keys %$Params)
    {
        if (!exists($ALL_PARAMS{$Param}))
        {   croak "$Param is not a valid parameter"; }

        $self->$Param($Params->{$Param});
    }
}

sub _ValidateParam
{
    exact_argcount(3);
    my $self  = shift;
    my $Param = shift;
    my $Value = lc(shift);

    if (!grep(/^$Value$/i, keys %{$ALL_PARAMS{$Param}}))
    {   croak("Invalid value '$Value' for $Param"); }

    $self->{$Param} = $Value;
}

sub BaseScore
{
    exact_argcount(1);
    my $self = shift;

    # Check all parameters exist
    foreach my $Param (keys %BASE_PARAMS)
    {
        if (!defined($self->{$Param}))
        {   croak("You must set '$Param' to calculate the Base CVSS score"); }
    }

    my $Score = 10;
    foreach my $Param ('AccessVector', 'AccessComplexity', 'Authentication')
    {
        $Score *= $BASE_PARAMS{$Param}->{$self->{$Param}};
    }

    # Calculate the impact portion of the score taking into account the weighting bias
    my $ImpactScore = 0;
    foreach my $ImpactType ('ConfidentialityImpact', 'IntegrityImpact', 'AvailabilityImpact')
    {
        my $Value = $BASE_PARAMS{$ImpactType}->{$self->{$ImpactType}};

        if ($self->{ImpactBias} . 'impact'  eq lc($ImpactType))
        {   $Value *= 0.5; }
        elsif ($self->{ImpactBias} eq 'normal')
        {   $Value *= 0.333; }
        else
        {   $Value *= 0.25; }

        $ImpactScore += $Value;
    }
    $Score *= $ImpactScore;

    # Round to one sig fig
    return sprintf('%.1f', $Score);
}

sub TemporalScore
{
    exact_argcount(1);
    my $self = shift;

    # Check all parameters exist
    foreach my $Param (keys %TEMPORAL_PARAMS)
    {
        if (!defined($self->{$Param}))
        {   croak("You must set '$Param' to calculate the Temporal CVSS score"); }
    }

    my $Score = $self->BaseScore();

    foreach my $Param (keys %TEMPORAL_PARAMS)
    {   $Score *= $TEMPORAL_PARAMS{$Param}->{$self->{$Param}}; }

    # Round to one sig fig
    return sprintf('%.1f', $Score);
}

sub EnvironmentalScore
{
    exact_argcount(1);
    my $self = shift;

    # Check all parameters exist
    foreach my $Param (keys %ENVIRONMENTAL_PARAMS)
    {
        if (!defined($self->{$Param}))
        {   croak("You must set '$Param' to calculate the Environmental CVSS score"); }
    }

    my $TemporalScore = $self->TemporalScore;

    my $Score = ($TemporalScore + ((10 - $TemporalScore)
                * $ENVIRONMENTAL_PARAMS{CollateralDamagePotential}->{$self->{CollateralDamagePotential}}))
                * $ENVIRONMENTAL_PARAMS{TargetDistribution}->{$self->{TargetDistribution}};

    # Round to one sig fig
    return sprintf('%.1f', $Score);
}

1;
__END__

=head1 NAME

Security::CVSS - Calculate CVSS values (Common Vulnerability Scoring System)

=head1 SYNOPSIS

  use Security::CVSS;

  my $CVSS = new Security::CVSS;

  $CVSS->AccessVector('Local');
  $CVSS->AccessComplexity('High');
  $CVSS->Authentication('Not-Required');
  $CVSS->ConfidentialityImpact('Complete');
  $CVSS->IntegrityImpact('Complete');
  $CVSS->AvailabilityImpact('Complete');
  $CVSS->ImpactBias('Normal');

  my $BaseScore = $CVSS->BaseScore();

  $CVSS->Exploitability('Proof-Of-Concept');
  $CVSS->RemediationLevel('Official-Fix');
  $CVSS->ReportConfidence('Confirmed');

  my $TemporalScore = $CVSS->TemporalScore()

  $CVSS->CollateralDamagePotential('None');
  $CVSS->TargetDistribution('None');

  my $EnvironmentalScore = $CVSS->EnvironmentalScore();

  my $CVSS = new CVSS({AccessVector => 'Local',
                       AccessComplexity => 'High',
                       Authentication => 'Not-Required',
                       ConfidentialityImpact => 'Complete',
                       IntegrityImpact => 'Complete',
                       AvailabilityImpact => 'Complete',
                       ImpactBias => 'Normal'
                    });

  my $BaseScore = $CVSS->BaseScore();

  $CVSS->UpdateFromHash({AccessVector => 'Remote',
                         AccessComplexity => 'Low');

  my $NewBaseScore = $CVSS->BaseScore();

=head1 DESCRIPTION

CVSS allows you to calculate all three types of score described
under the CVSS system: Base, Temporal and Environmental.

You can modify any parameter via its accessor and recalculate
at any time.

The temporal score depends on the base score, and the environmental
score depends on the temporal score. Therefore you must remember
to supply all necessary parameters.

=head1 POSSIBLE VALUES

For meaning of these values see the official CVSS FAQ
at https://www.first.org/cvss/faq/#c7

=head2 Base Score

  AccessVector            Local, Remote
  AccessComplexity        Low, High
  Authentication          Required, Not-Required
  ConfidentialityImpact   None, Partial, Complete
  IntegrityImpact         None, Partial, Complete
  AvailabilityImpact      None, Partial, Complete

=head2 Temporal Score

  Exploitability          Unproven, Proof-of-Concept, Functional, High
  RemediationLevel        Official-Fix, Temporary-Fix, Workaround,
                          Unavailable
  ReportConfidence        Unconfirmed, Uncorroborated, Confirmed

=head2 Environmental Score

  CollateralDamagePotential  None, Low, Medium, High
  TargetDistribution         None, Low, Medium, High

=head1 SEE ALSO

This module is based on the formulas supplied at:
http://www.first.org/cvss/

=head1 AUTHOR

Periscan LLC, E<lt>cpan@periscan.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright 2006 by Periscan LLC

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
