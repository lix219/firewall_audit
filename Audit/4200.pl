#!/usr/bin/perl -I /home/fw_audit/script/lib

use Firewall::Common qw/open_db record pass/;

sub	port_redundancy{
		my $g_key = shift;	#$g_key	name:type:port1:port2
		my $type = shift;
		my $lower_bound = shift;
		my $upper_bound = shift;
		my @arr = split /:/,$g_key;
		print "****************$arr[0],$lower_bound, $upper_bound*****************\n";
    	foreach my $key (keys %global_map) {
    		my @arr2 = split /:/,$key;		#key name:type:port1:port2
    		#my @arr3 = @global_map{$key};	#type port1 port2
    		if ( $type == $arr2[1]){
    			if ( ($type==6) || ($type==17) ){	#tcp/udp
    				if ( (@arr2[2]>=$lower_bound && @arr2[2]<=$upper_bound) ||(@arr2[3]>=$lower_bound && @arr2[3]<=$upper_bound) ){
    					if (exists $ser_4200{$arr[0].$arr2[0]}){
    						print "$arr[0] and $arr2[0] already exist\n";
    					}else{
    						$ser_4200{$arr[0].$arr2[0]} = 1;
    						$ser_4200{$arr2[0].$arr[0]} = 1;
                            pass $tid, 4200,'fail', "自定义服务组$arr[0]与$arr2[0]端口段冗余";
    					}
    				}
    			}else{	#icmp or other protocols
    				if ( ($arr[2]==$arr2[2]) && ($arr[3]==$arr2[3]) ){
    					if (exists $ser_4200{$arr[0].$arr2[0]}){
    						print "$arr[0] and $arr2[0] already exist\n";
    					}else{
    						$ser_4200{$arr[0].$arr2[0]} = 1;
    					    $ser_4200{$arr2[0].$arr[0]} = 1;	
                            pass $tid, 4200,'fail', "自定义服务组$arr[0]与$arr2[0]端口段冗余";
    					}
    				}
    			}
    		}
		}

}

sub _4200 {
    our $tid=shift;
    our %ser_4200 = ();
    my $dbh = open_db;
    my $sth=$dbh->prepare("SELECT defsrv_name, defsrv_type, defsrv_from_port, defsrv_to_port FROM  cfg_defser_grp WHERE task_id=$tid")
       or die "prepare failed:".$dbh->errstr();
    $sth->execute() or die $!;;
		our %global_map;#key=custormize group name  value=array which stores two integer representing the range
		
    while(my @row_ary=$sth->fetchrow_array()){
            
        #print "@row_ary\n";
			#print "$row_ary[0]\n";
			#my $g_name=$row_ary[1];
			#my @g_range= split(/-/,$row_ary[2]);
			my @g_range= ($row_ary[1], $row_ary[2], $row_ary[3]);
			#print "$g_name $g_range\n";
			my $g_key = join ':',$row_ary[0],@g_range;	#$g_key	name:type:port1:port2

			$global_map{$g_key}=\@g_range;
			#print "@g_range\n"
            #print "@row_ary\n";
    }
    foreach my $key (keys %global_map) {
				@arr=@{$global_map{$key}};
				delete($global_map{$key});
				port_redundancy $key, @arr;
			#	foreach my $item (@{$global_map{$key}})
			#	{print "$item "};
			#	print "\n";
		}
    print "OK\n";
    $sth->finish();
}


#_4200 2015;
1
