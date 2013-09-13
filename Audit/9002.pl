#!/usr/bin/perl -I /home/fw_audit/script/lib

use Firewall::Common qw/record open_db pass/;


sub _4002{
    #4002:detect acl protocol
    #pass 4002:protocol isn't ip
    #fail 4002:protocol is ip
    my $tid=shift;

    my $dbh = open_db;

    my $sth=$dbh->prepare("SELECT protocol FROM cfg_acl WHERE task_id=$tid")
       or die "prepare failed:".$dbh->errstr();

   #record 'DBASE', $! unless $sth->execute;

    $sth->execute() or die $!;

    while(my @row_ary=$sth->fetchrow_array()){
        if($row_ary[0] =~ /ip/i){
        pass $tid,4002,'fail','网络协议不能为ip';
        }else{        
        pass $tid,4002,'pass','通过';
        }
    }

    $sth->finish();
}

#_4002 1894;
1


