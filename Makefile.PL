use inc::Module::Install;

name        'Iodef-Pb-Format';
all_from    'lib/Iodef/Pb/Format.pm';

requires    'Module::Install'   => '1.00';
requires    'Iodef::Pb'         => '0.01';
requires    'Snort::Rule'       => '1.07';
WriteAll();
