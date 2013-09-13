#!/usr/bin/perl -I /home/fw_audit/script/lib

use Firewall::Common qw/open_db record pass/;

sub port_redundancy{
        my $ser_grp = shift;
        my $g_key = shift;  #$g_key name:type:port1:port2(:group)
        my $type = shift;
        my $lower_bound = shift;
        my $upper_bound = shift;
        my @arr = split /:/,$g_key;
        print "****************$arr[0],$lower_bound, $upper_bound*****************\n";
        foreach my $key (keys %ser_grp) {
            my @arr2 = split /:/,$key;      #key name:type:port1:port2(:group)
            #my @arr3 = @ser_grp{$key};  #type port1 port2
            if ( $type == $arr2[1]){
                if ( ($type==6) || ($type==17) ){   #tcp/udp
                    if ( (@arr2[2]>=$lower_bound && @arr2[2]<=$upper_bound) ||(@arr2[3]>=$lower_bound && @arr2[3]<=$upper_bound) ){
                        if (exists $ser_4201{$arr[0].$arr2[0]}){
                            print "$arr[0] and $arr2[0] already exist\n";
                        }else{
                            $ser_4201{$arr[0].$arr2[0]} = 1;
                            $ser_4201{$arr2[0].$arr[0]} = 1;
                            $sign_4201 = 1;
                            my ($ser1,$ser2);
                            if ($#arr == 3){
                                $ser1 = $arr[0]
                            }else{
                                $ser1 = $arr[4]
                            }
                            if ($#arr2 ==3){
                                $ser2 = $arr2[0];
                            }else{
                                $ser2 = $arr2[4];
                            }
                            pass $tid, 4201,'fail', "服务组$ser_grp存在冗余服务$ser1与$ser2";
                            
                        }
                    }
                }else{  #icmp or other protocols
                    if ( ($arr[2]==$arr2[2]) && ($arr[3]==$arr2[3]) ){
                        if (exists $ser_4201{$arr[0].$arr2[0]}){
                            print "$arr[0] and $arr2[0] already exist\n";
                        }else{
                            $ser_4201{$arr[0].$arr2[0]} = 1;
                            $ser_4201{$arr2[0].$arr[0]} = 1;    
                            $sign_4201 = 1;
                            my ($ser1,$ser2);
                            if ($#arr == 3){
                                $ser1 = $arr[0]
                            }else{
                                $ser1 = $arr[4]
                            }
                            if ($#arr2 ==3){
                                $ser2 = $arr2[0];
                            }else{
                                $ser2 = $arr2[4];
                            }
                            pass $tid, 4201,'fail', "服务组$ser_grp存在冗余服务$ser1与$ser2";                            
                        }
                    }
                }
            }
        }

}


sub _4201{
    #detect service group redundancy:redundant services in one service group
    
    our $tid = shift;
    our %ser_4201 = ();
    my $dbh = open_db;
	our $siign_4201 = 0;
    my $sth=$dbh->prepare("SELECT ser_grp_name,ser_member FROM cfg_ser_grp WHERE task_id=$tid")
       or die "prepare failed:".$dbh->errstr();
    $sth->execute() or die $!;
    

    while (my @row_ary=$sth->fetchrow_array()){ #one service group
            #our %ser_grp;
            print "================================$row_ary[0]============================== \n";
			our %ser_grp = ();    #hash of services and its info
            my @member = split(/\s/, $row_ary[1]);    #array of services in one service group
            foreach my $ser_name (@member){     #get detail of each service, may be a service group     
                print "$ser_name \n";
				my $sth_ser = $dbh->prepare("SELECT defsrv_type,defsrv_from_port,defsrv_to_port 
                    FROM cfg_defser_grp WHERE defsrv_name=\'$ser_name\' and task_id=$tid")
                    or die "prepare failed:".$dbh->errstr();
                $sth_ser->execute() or die $!;

                while (my @ser_info = $sth_ser->fetchrow_array()){  #only self-defined services
                    print "service:$ser_name\n";   
#                   print "@row_ser\n";  
                    #my @ser_info = split /\//,$row_ser[0];  #split protocol type and port
					#$ser_grp{$ser_name} = \@ser_info;
                    #my @g_range= ($row_ary[1], $row_ary[2], $row_ary[3]);
                    #print "$g_name $g_range\n";
                    my $g_key = join ':',$ser_name,@ser_info;  #$g_key name:type:port1:port2
                    print $g_key."\n";
                    $ser_grp{$g_key}=\@ser_info;
                    print "$ser_grp{$g_key}\n";

                    #print "@g_range\n"
                    #print "@row_ary\n";                      
                }   
                $sth_ser->finish();

                #service group 
                my $sth_ser_grp = $dbh->prepare("SELECT ser_member 
                    FROM cfg_ser_grp WHERE ser_grp_name=\'$ser_name\' and task_id=$tid")
                    or die "prepare failed:".$dbh->errstr();
                $sth_ser_grp->execute() or die $!;

                while (my @ser_grp_info = $sth_ser_grp->fetchrow_array()){  #
                    print "service group:$ser_name\n";
                    my @member = split /\s+/,$ser_grp_info[0];
                    foreach my $mem (@member){
                        print "service $mem in group $ser_name\n";
                        my $sth_ser1 = $dbh->prepare("SELECT defsrv_type,defsrv_from_port,defsrv_to_port 
                                                    FROM cfg_defser_grp WHERE defsrv_name=\'$mem\' and task_id=$tid")
                        or die "prepare failed:".$dbh->errstr();
                        $sth_ser1->execute() or die $!;

                        while (my @ser_info1 = $sth_ser1->fetchrow_array()){  #only self-defined services
                            push @ser_info1,$ser_name;
                            my $g_key = join ':',$mem,@ser_info1;  #$g_key name:type:port1:port2:group
                            print $g_key."\n";
                            $ser_grp{$g_key}=\@ser_info1;
                            print "$ser_grp{$g_key}\n";
                            #print "@g_range\n"
                            #print "@row_ary\n";                      
                        }   
                        $sth_ser1->finish();

                    }                                       
                }
                $sth_ser_grp->finish();

            }

            foreach my $key (keys %ser_grp){
                my @arr=@{$ser_grp{$key}};
                delete($ser_grp{$key});
                port_redundancy $row_ary[0], $key, @arr;
            #   foreach my $item (@{$ser_grp{$key}})
            #   {print "$item "};
            #   print "\n";
            }



	}  #end of one service group

		
    if($sign_4201 == 0){pass $tid,4201,'pass',"服务组$row_ary[0]不存在冗余服务";}													
	
    $sth->finish();
    print "ok\n";
}

#_4201 2015;
1

