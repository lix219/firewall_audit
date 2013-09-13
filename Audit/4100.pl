#!/usr/bin/perl -I /home/fw_audit/script/lib

use Firewall::Common qw/open_db record pass/;


sub _4100{
    #detect net group any
    my $tid=shift;
    my $dbh = open_db;
	my $sign_4100=0;

    my $sth=$dbh->prepare("SELECT net_grp_name,net_ip FROM cfg_net_grp WHERE task_id=$tid")
       or die "prepare failed:".$dbh->errstr();
    $sth->execute() or die $!;

  
    #my @net_grp;

    while(my @row_ary=$sth->fetchrow_array()){
            #print "A@row_ary\n";
            #push @net_grp,$row_ary[0];
            my @arr=();
            @arr = split(/\s+/,$row_ary[1]); #某地址组ip
            foreach my $net_ip(@arr){
                #print "test1\n";
                if($net_ip =~ /any/i){
                    #print "any\n";
                    pass $tid,4100,'fail',"地址对象组$row_ary[0]包含任意地址";
                    $sign_4100=1;
                    last;
                }                    
            }
    }
	if($sign_4100 == 0){pass $tid,4100,'pass',"地址对象组不包含任意地址";}


    print "ok\n";
    $sth->finish();
}

#_4100 6;
1
