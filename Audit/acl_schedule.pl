
#acl_schedule($tid, $acl_id1, $acl_id2)



sub acl_schedule {
    #判断两条策略生效时间是否有交集

    our $tsk_id = shift;    #任务id
    my $acl_id1 = shift;
    my $acl_id2 = shift;

    #到cfg_acl表里读策略对应的时间字段
    #'always'和任意时间段有交集
    #两条策略时间字段都不是'always'，再具体去fp-schedule表里读数据比较

    #如果两条策略生效时间段有交集， return 1 ；否则return 0.

###############################################################################

    sub getDT {
        my $acl_id = shift;

        # 从数据库中获取原始时间对象
        use DBI;
        my ($host, $user, $pass, $db) = qw {10.109.32.166 root 123456 fw_audit};
        my $dbh = DBI->connect("DBI:mysql:database=$db;host=$host", $user, $pass);

        my $sth = $dbh->prepare("SELECT `fp-schedule`.`VALUE` 
                    FROM `fp-schedule`, `cfg_acl` 
                    WHERE `fp-schedule`.`tid`=`cfg_acl`.`task_id` 
                    AND `cfg_acl`.`task_id`=? AND `cfg_acl`.`acl_id`=? 
                    AND `fp-schedule`.`STRING`=`cfg_acl`.`schedule`;");

        my $value = $sth->fetchrow() if $sth->execute($tsk_id, $acl_id);

        $sth->finish();
        $dbh->disconnect();


        # 统一为标准的时间格式
        use Time::Local;
        $value =~ s{\b(\d{2}-\d{2}-\d{2})\b}{20$1}g;

        $value =~ s{
            \b(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(:(\d{2}))?
        }{
            timelocal $7, $5, $4, $3, $2, $1;
        }xge;

        $value =~ s{
            \b(\d{2}):(\d{2})(:(\d{2}))?
        }{
            $1 * 3600 + $2 * 60 + $4;
        }xge;

        $value =~ s{^(\d+~\d+@\d{1,7})$}{0~2000000000 $1};


        # 绝对时间和循环时间的构造过程
        # 设置默认时间为 ALWAYS，除非匹配并执行下面的绝对时间和循环时间构造代码
        my $self = {
            TYPE   => "ALWAYS",
        };
        $value =~ s{
            ^(\d+)~(\d+)$
        }{
            $self = {
                TYPE   => "A",      # 类型 A 代表绝对时间
                START  => $1,
                END    => $2,
            };
        }xge;

        $value =~ s{
            ^(\d+)~(\d+)[ ](\d+)~(\d+)@(\d{1,7})$
        }{
            $self = {
                TYPE   => "R",      # 类型 R 代表循环时间
                START  => $1,
                END    => $2,
                TSTART => $3,
                TEND   => $4,
                WEEK   => $5,
            };
        }xge;

        return %$self;
    }

    my %dt1 = getDT $acl_id1;
    my %dt2 = getDT $acl_id2;

    printf "%-10s%-16d%-16d%-10d%-10d%-10d\n", $dt1{TYPE}, $dt1{START}, $dt1{END}, $dt1{TSTART}, 
                $dt1{TEND}, $dt1{WEEK};
    printf "%-10s%-16d%-16d%-10d%-10d%-10d\n", $dt2{TYPE}, $dt2{START}, $dt2{END}, $dt2{TSTART}, 
                $dt2{TEND}, $dt2{WEEK};
    # 遇到系统内设的 always 时间对象，直接返回有交集
    return 1 if $dt1{TYPE} eq "ALWAYS";
    return 1 if $dt2{TYPE} eq "ALWAYS";

    if ($dt1{TYPE} eq "A" and $dt2{TYPE} eq "A") {
        return 0 if $dt1{END} < $dt2{START} or $dt2{END} < $dt1{START};
        return 1;
    }
    elsif ($dt1{TYPE} eq "R" and $dt2{TYPE} eq "A") {
        my %tmp = %dt1;
        %dt1 = %dt2;
        %dt2 = %tmp;
        print "$dt1{TYPE} $dt2{TYPE}\n";
    }
    sub cmpWeek {
        my ($w1, $w2) = @_;
        foreach (1 ..7) {
            return 1 if $w1 =~ m/$_/ and $w2 =~ m/$_/;
        }
        0;
    }
    # 判断绝对时间与循环时间对象之比较
    if ($dt1{TYPE} eq "A" and $dt2{TYPE} eq "R") {
        return 0 if $dt1{END} < $dt2{START} or $dt2{END} < $dt1{START};
        return 1 if ($dt1{END} - $dt1{START}) > 604800;
        # 晚上完成下面的任务
        # 一周以内的时间比较
        my $week;
        my $sdok = (7, 1, 2, 3, 4, 5, 6)[(localtime $dt1{START})[6]];
        my $edok = (7, 1, 2, 3, 4, 5, 6)[(localtime $dt1{END})[6]];
        print "$sdok $edok\n";
        if ($sdok < $edok) {
            $week = join "", $sdok .. $edok;
        }
        else {
            $week = join "", $sdok .. 7, 1 .. $edok;
        }
        print "$week\n";
        # 比较连个跟对象的星期元素是否相交
        print "$week $dt2{WEEK}\n";
        return 0 unless cmpWeek $week, $w2{WEEK};
        my $stime = (localtime $dt1{START})[2] * 3600 + (localtime $dt1{START})[1] * 60 + 
                (localtime $dt1{START})[0];
        my $etime = (localtime $dt1{END})[2] * 3600 + (localtime $dt1{END})[1] * 60 + 
                (localtime $dt1{END})[0];
        # 比较时分秒
        return 0 if $etime < $dt2{TSTART} or $dt2{TEND} < $stime;
        return 1;
    }
    elsif ($dt1{TYPE} eq "R" and $dt2{TYPE} eq "R") {
        return 0 if $dt1{END} < $dt2{START} or $dt2{END} < $dt1{START};
        # 这里好像缺了点什么
        return 0 if $dt1{TEND} < $dt2{TSTART} or $dt2{TEND} < $dt1{TSTART};
        return 0 unless cmpWeek $dt1{WEEK}, $dt2{WEEK};
        return 0 if $dt1{TEND} < $dt2{TSTART} or $dt2{TEND} < $dt1{TSTART};
        return 1;
    }
}

print acl_schedule(2013, 8043, 8044);
print "\n";