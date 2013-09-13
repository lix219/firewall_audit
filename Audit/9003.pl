#!/usr/bin/perl -I /home/fw_audit/script/lib
use Firewall::Common qw/record open_db pass/;


sub _4003{
    #4003:detect acl source ip
    #pass 4003:source ip != any 
    #fail 4003:source ip == any
    
    my $tid=shift;

    my $dbh = open_db;

    my $sth=$dbh->prepare("SELECT src_addr FROM cfg_acl WHERE task_id=$tid")
       or die "prepare failed:".$dbh->errstr();

#    record 'DBASE',$! unless $sth->execute();
    $sth->execute() or die $!;
    
    while(my @row_ary=$sth->fetchrow_array()){
        
        if($row_ary[0] =~ /any/i){
            pass $tid,4003,'fail','源ip地址不能为any';
        }else{
            pass $tid,4003,'pass','通过';
        }
    }
    $sth->finish();
}

#_4003 1894;
1
