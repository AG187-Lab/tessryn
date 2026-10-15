"""Adversarial parser fixtures, derived from diagnostic captures.

The embedded inputs contain only original guest diagnostics and compiled label
metadata; no host paths or raw failed host logs. They are self-contained unit
fixtures, not retained capture receipts or clean-source execution evidence.
The compressed representation keeps three complete context traces manageable;
mutations below operate on decoded, ordinary marker/field lines.
"""
import base64
import copy
import json
import re
import unittest
import zlib

from tools.k02_region_trace import parse_transcript

# Original diagnostic 3 traces, intentionally not used as qualification proof.
_FIXTURES = {
    'sharing': (
        'c-rk<ZI9x{vi>V*KIcgN-t9<ym~7Z+wJ)=GW|Dg&9SODDZ3cw_Vw>5W6Xn0(YQKPOY%t(un4I;l24m=Qb#>MARJGgYuPc8#52o|U)sKH&1vWO('
        'beSw7_s)jXaX6jX@gfXkn_T^fk(5&WkbV$7X*ht9V(N#h_(2mcu714YD4-k>YLVuFmYfphBcuey#z#Dq2x;wwgfOO=Cj%_8)l}Hf_b}q{!4=4w'
        '{>P5}=fuWWKPvV24_C`*F^TkJ>{QatdQpl=SuH^o`{8OjkCSL+lIdbz2>k0RvJ>}SkF_z2)jWZokCR9*L3ySW4HZHtR6GcffIVat;@O_BK)Frp'
        '*=%8SVw>7pjY!rOlWdPw+pdy_MKn#G$E*3HUN(u~9-^5Dg)<R;i-_l`odr!IWKf9Eyh((wgYl!DOiisZc8z@s-A)?^K4Q&{7fT!I)VNgv)Cmwl'
        'A;9Bp0-kIXZ#O5dxmq{(o13rV=W%3bR>$=rFs{9~?!0O2yjjd<(}t5<*VwF$A2u4_M2k2cFZHB;YUx@tQ+SSKStqKk1JHWX;yK(08QHMYCa<$!'
        'r%6*gkHWBJ=JHXth2?gkp3a~N3Q_TK<5p=ho$J}YAVI}x(<9E&y{e2TPTD<`u6rx;-qxBgB0HVbhlr)_Wizh;_Y&D)RSne^Rs^YhY;<<+>KPZH'
        'sM%`DT~m#Vpa%EA+h<&WH;1#u7jVrmv{6k&;6#Le;najSdB!rDJ~_vT?4K(eCr$mfwCFc#jLSkqoM`h$lK?6U9eCIzAhJ5hn)n!C%lDXNl7Znk'
        '<rH2SQ`9rM-efVKxp-_byC%gz8{IU}&4HXYCF?-uc_7!Dwhgr`#!H6Tc-0&3IBU3eY^<6FJF>0FjZJZ0#+sWxE&gaeX;=UUk@=p#-O_>fa=9Il'
        'sgp`oh|nk>=Sru6-B*5Tj49oOVh(g!Gbf_b(3-_OXb)w7O_!E8xpoX}l{AM&$~S>1+%mLHZVCPje7~dTzA6I4q9#Dd1T-`xxM;|{riQHp?a`vk'
        'zTaf)wBZuQtFhN9RS;5$V7kd_Ux4AY4|=yMVNDTPm}Pq)0dl4+Guo5zaF4ZTG#Ex?Z_a{QRYYS}f*Dsk@($&ZJ&A=U$j;0GMq+nrfEf`x$RATh'
        'cG0_}UORs?p_&OAdrWOnFrfnPCt0kN+)1P0E3G_<36_maNC<AFIxM8xOJ<6oy=(;)0ouby7-6x+I7EnjltMk(${Cnb)xru`a<T*WF;GP-vSWpD'
        '8+LPn_JXtUcnkVsfa=}&Dk?tP0H6T(dk_+1Mq4ltlS<^4J1r_6-3((=;e9wo3H`fN8Db(lWw8;&hXEnNkdP@sLTj-0v{J?jDTLsV*=S!H?Q1KH'
        'K?;CUd%je)%8(&XfOx;T9)!$WmFhtPnGD)p5Bhsc3ZE1?L69fWWw7?!b91sQH}?<E&Ha6OwYBT|Q*P%>{u(cu=`>9fA*;?s_~CXI<L^q%**XD|'
        'ys2pmlL=KMdLC|4`ryPgYXV?D2Xj5zMoU4xm!Fi%?MlzjBPP_VS(2X{N$Y`0wvr{H5iYlEW$eHf?f`t<U>+Asw#1}W5nie_DJ)F<b`cw`jYN_%'
        'oVD>x;S+gpn$v~Gc!2P1c6d>O=E9?a3A~*?OPROVDH)ZmUdKz=>{obBZut%2e4k@bEZat&da7k;1;KmAjw{|aI8=!;Mta!T&=^c9&>{DYCE#mP'
        'ht{K-7@`AV8IelE2ih_wg3uSrrx*e~AWGXNj0E|A*l2EN;|J(90QiIb>bxT0S~{1+IleHobKCQA=S}7l1<2yi*ARcm2Q^JVFhmn(#_e&)slcPC'
        's~RN{p^)$wivY4^NS}m-f1zaXjtD5|C6QcMc;~sljIoeIOA$aj2A^A!s?HHhV^sj@6j9r>LFI>tiw{>2S$9O|HWDn0n{4yo4B2s9wbJ_SdM9fo'
        'YA33{cjpNkOs(Bl)z+En@49^6ezcFxOZ5-Y>)42u;2qM<(WP79d0}-ti*euW`o-XaJOcg(nTJSQaYJODCFF8Q?)jSS8U&XACAKUrwJ$|M8aTN;'
        's<M+qlC)Qzaq@s-c_>5{OPfxqV$jIC3G1RC$l=03l+hw?%6?FiCpyR@===74`@WrRyIQ9O(?>nAzDx4f<&$ui-QpxztXu+lKf1fS{r%JUJ;LMB'
        'r~BLA|2@wS4Q_7V{qpY9^@qXx(e0<vhxG^Pci-M#e;obv>)W@Z+X19g$toVY#OrzRWf~+8Lkxg8cz}HFAsGS&!B?VbV6($cogw;K<O%~w{2p~O'
        '^e55RK@2HrTEh)p`u0Uf_Fs_7#fzD(p8mtT-$vux>rcOo?gnWeT}~GzAT|io3NAlt=K&nEC~#T9Ae*QtzG+b?Hb?VsVw@gxN#N#tc73dnm$x*L'
        'PRs)w$v}D#xtX3vJAQzU57A(<*hpD-*B#8nKv87f;cC}DUxU?u8Q+esfBt=7BAT9$d9G<%hsQ%PfV}+)c3kN@SUx<*Q=?~Nf11QYI51i1$cdMs'
        '+iY&+$byZ`Vrhr7#TRGPCp&kB*0bvAZ%22d`|;<Scc1QIXmt=oHjY7Br~?Y6{ov6;0vrriP=Eg`?`~DV$I-`|+uz3@uRo7}yZ-R*=fUQ>b3DXY'
        '6}|wPrb@ZFxOm7Z#b}_D#6B*QA+CxX{olL$@lQ85_v5?K?QieijPAxa@2g*V^ZD2D&HsKH{aiCy6fd)3<spH0(`D)+)*7h?lOP!`zRYbfn6CE{'
        '=xn-I7Ei{XZ*Shd`!L!zwpp&m=>*>p51=QmxS81}JA)4g^RMH0wOlTu#0Ky&ytQ*Tg6_@IOoR1XaEjT&2dPj~%;Q-)Jqk7-%ruv!FPVse_ClzE'
        'b(1wPj;=FR{~?8m#y^d~k07A_T-mv?uDOdlC`Teta*$85I!*E`@Ix{vX8Y0-W9W%y!G$f>qH)CvVLXYm5Qk2>zwvVn7Mo>z;B+>E-7p^KUz)7<'
        'a?IKsm<5UZZeab@q-2Lh{51yucT$!^H(zU>$6<P?S>ZR=pEt^qL9lq#)3oOg?ljQ<r*y)2;ATwY*&>1OxZR1J=Tp_Lhj5^1*kbSNH}4^EH)o>x'
        '2{K#^!Nv~uG9XHe!lBUCAgGjyg(^uhfM(^^RA3QO?jb@6QARQ1gSYz94-gML8~BPV%ss+1X;$R^`tJQk3%2QRv{+;a8EU75Sp*P$xkG2j>2kXP'
        '3{mvF#<Vp;7DvbiGfR!}=4dvlkQ%ajsAACE*9xiWnG63b$tC6ECCRvUup+zsri+buVIxx5$fl`%lZ{e5J<dk7(MIHC8?hD}(bH@MOz`W+QkV<i'
        'pZE_KkA*{3m92VL2DKaeWI&u*Ck(-|j#MZeq~t>UK@`sPB;6mRvq@?9<JF^eKo}wT0A6tRLb4ZHIsuFv%Z~EwMPx5Bdr{eomy0RH<??VY5YzlM'
        '6BPm+WPysX-~qwdXhJn6nD9Vy%@|cyawUxxl3FB<vP@ZGsS#2dYNcnj5QwWfoxK@-zJGV~2~gMoExNR5V5123($kkM7X)idtu4gFwly=Gv^e{1'
        '835(hFxEz{lTw|B6O=8W57ID#D5Nn_CA%_irYJkOPS@P@Owp-96illj5Kn=e*3O+050DDZ+ytNKCZ+Q@cM*lZ=zQb(mb(wb)qgGCw2`{;D#$^M'
        ';=ZH`8zeo=nJ|V)%OKyB9#z6}ZGEa~=wn|pC8!7_@}SHQEtbl(h3)_RI=Z{x47e%=+_7+Kr{!Xr(QrwvnVnA{aR<9T>De?W0c`pvO9?n*+)c@I'
        '!X&ehvEkZW7jB$E*?y0Yow35rQ<ueIxx00<#aya7`VFd|jm^Azmf$Wgf%(8Vh1FP=R+m`41ifs~0J#QouL)!@v=whZ-+a0&Cst@{=qiJ<SUP^n'
        '7{paz$c^2~mi)bvxS)*&Kx~hX(<Djv0cUOWl%<#pAhyM9=w7GumF>n17#~j!hhj;}4QR~`M+ZI4f}Zvn^c$<UQ%Rpee-M>mM*F4`Oitz!r_}{='
        '3CY}wWNuX&*Ozp!68dt7zqyxTObDg!GXZIbQZLUqn4V5Kq$}mrDTW`(DBtMfNoUHztj;;1JN_*hr%4N5*TR6@=-gU}ZT?MtL?>rAh^(vf=W1%>'
        'Z#yszsesy*3Xmcd;M=JHI!_AV9i0LkOaZkN;3BaaU1SQNdaou4Iz0tY7g<iy%&q7}yVVPlJi(`vJnc&I^o8q6-V@0a(tlw|4rdcWcd-fGQCO0*'
        '7M6q^&noJ)!tx@+pImf-8L-~jg`dtYpw$Jk3(MS#W$r~T+r3_rWyI+$!@9CeeJK+?kY&iBEOS`t+U4q|++51a_@%g`rR&vA(wRecRwS(85ZXRD'
        'Nh;_4W*l-tWpXHX)HviKgS>RYG|0(CaY)!ZhtM7>l<*=sglF!>Uxj<UAcxQ%Diz+9L+Ti=E^BFES9GUj7rOHT-Bo|{P3heu-5{Oj<qO`BT@$1i'
        'i#Wb7Md)QIg6;kK5oKHBSR1-dTK)H}Mey@Y<XZvBr26lWNh8e(Va5~KC@;j)hMx9#7*ghk3KO3SMFmoXX~um_1jnJKRQf=TA@+T*D-`o$#B*37'
        '7ql3GT<D|`74@Y4z)2&%>k>rggrCZ-u{&@z0%@iOQlbWOdcsfD@$6vf%dAEqS=f_4!@i!0HBJ`w81{!H`n2~;5!5@GO`KM*W;FtNVfWfzc5vuw'
        'g!6C?L#K1j(W?>U>rDR{-i7t+%gwTL`rk9gGjcS>9~|SIE;qk$FrtgZc-}k4GkQA4^H+4a`NG`lB~hH6j^amOZhobcIE?Q?aeDY9&R!HhU=oKN'
        'e?Q5=^RYDuzsQNxi(D~8IO!e2Prm`hX?1}RE;6?g7wuLrI1kTyxD!Qmg>dl?NyNQf^YG&EM7-y#s~jDT;s-}@4aHwYxLpQ{%id9(<I_=GUL=ak'
        '%&p{i6mLdxPEJR0*%ig*KO+(6JJ(yvm%W<G+3|BJ{97!t{4btMVQZ|EwbiT*2o4{4vIWG~7lk^3Iqy2FvP-|tj*#hn8k}z~dX-?Eoq2wRz25ni'
        't*4c6kzZTXA($(BhGpYJOLV9evDRmThFn?<bYhf*|0F=6mA)24OYK|b`5qQndklNR1eh9Zg~F^^pS$~;vO}&fHAYs)?rBh|I-R1Vi~BcRWaX-U'
        'k@cY4?~b{|+N6b7*W#et?|RZgpzRCJhu(hImnyif%7M4v9ivBONv$B;OKL;#KO3CBq_+Be6?%LrB~L4*UPaD(8KsnGwu!hO78dOEk_xoz><8b5'
        'gLjoyDswaSy|ijBtpq>4v{GG5E7j9|^W>bRRTD#qzVDkSN8BbZWZ(DAAEkx*Cil%BrHa@8ee-+us1Uc@%3|^d-uHehjKsUjd-dWs=Sy;YW^pK^'
        ')G~`#0r?k^SqOB<B<(?&g`_8E7EZhKP1YWqS$LV7dEYaO=FCE}(=!XNYi8l?`89--Z`S`7nMIX4ww{7>Aa&r*)FF0JhgVRCc&UYUQXWkm2SY}U'
        'I!=!1Zj;0R0P2uD{ASdlPNoj0-33zz&hP2c7wu;+$sJw~4-iFN$wU7$)@`WWkM2Y-zJgjE|IE&V1G;{f%&UmF%Ru&~>BfGLU7h~$PI*Xi_yWkD'
        '-;U*fNA{K{L-+8UPTcu+%=#~2dao4O*-m6%-v{aShwSdh7`t3HRqOfV{IaQQ*bv6s5VLFHSHt9<+B@e;%2Ru|HnoTPxi+Zw&bgjNi*9qSXHliY'
        'oa;IC@X$W@2+LZKnihDM7Pz|>c%OTmMGMl&J<g&E-R~Z~>+v@I39*e1rKcR{zhbokLR11mR06{8J>>fqaa7!&*7`?!a(}UJ5yx4ykewEBoJAG2'
        'e-X!7^zin%N5%bFO$*vj7{ZD6`Nw(Gz?~fAJi3tm9@4uaHE6<!Zj?9?n?7IP-IXP?>aVXs;<zwi<{<y|yY$Be-7jOudDdsYCgb?aG%*kEF>?Q&'
        'U;X|6hQVP8'
    ),
    'revocation': (
        'c-rk<ZExeYvi>VZKKB58Csn{7(yg~x>`V40Y40s?0E40^$EahwlAPU~qW}F4^<qo1WXrbJae7v}h$Y$_4u><(Jfvv(uPc8#52o|U)sKH&1vWO('
        'beSw7cV)xrIGoPxcoBxNO|E{#NJ=SwNZ*K_G!$T@nEK%=e$a%As~@j~HJozzn9q=>Sl|mo0~=bOQQs4R7wW)LghPRpFR%_U@j~U3fE%KqR9=Cs'
        '>3{6le@<+C^`laM|8TX87L!On#!e;OtQV!2l+_Ycu^+Cc^EioCCYdhgg}}eAB0F){daR9EtmX;ye4Ipj3Cc62Xs8fEq2fV+1e_tO5YNth1<Gw|'
        '&t?mw6WdhRYDBWSm}F<HT6dK^ETU=hJYLNo^|DC>_YloQD4dD#TSPoh?JQ^#A%jAM=1n4e9gH9KWNK=av8(J;=yqB;@DXdSyja>ur^c-cpiY1Y'
        '3IQH(6YylCc)L1r)z!MX-&}naKaV3jvpTL1fpPV{b>~fE=gnd^n>I9VU1hU2e%NSy6D{I+ywsC=)6&&urtloevQAWM2cY$&#dEk1GO}T(O<rfe'
        'PLrm39>i2`E+1t_Sgsf9=?to%5EXAX9+fK7xt{F{5>zysmN-ZEsxqQDY4=dN?ybmsTdTf^>~vBeB9^+B&AbBKOJsvpHB?(z5v205(OKKo78jtX'
        '*{aH2RgH_F2KT_*EiS;D!`b2sxMmpIs3szCB0|4#YC@YlV;N1KoMS}x&y|gnrhWr>=KV&Eaao9n6K(!z5<q340}q=7L{<k`6(0j^`5v=OGB6y#'
        'I)zup6!na*S6R$wE*@LVu1PV_MmG&~b0DWx$vTjE9?12oZ9^@K@seRSUiFGQS`F8ZjaAcNN46EYu_@YRthwsb;*aJ=!vZ*n%+LJonhvy=%k6+n'
        'om8qqghu%|S2_*ZedU+Nn9@xs=0KNKb0R7gty#>2_E7fM>C*Bh*N!1uCC#Cc=9@qiZW-Dpw*-HNe7~dTzA6I4q9#Dd1T<76xTwgyri!ft?a`vk'
        'zTaf)wBi!RtFhN<svx8g!E}?=zCec8KIq-5gf&HEVV0eN1mH{=GulIVxX0QV4Tcff%ULk1ifCjdm~pj(cPNkSAr_t>JDCHF#BOSU84){@Kc<T8'
        'O7D_-?fIJt)tsQQ$JAB|CRE`4Nfs+5ccxMBmDW6o36_nSkPzIO>adV%Z!%K^?afv&BS3rd5k^>SWgH^JzLY{e*_tyjr>Z3@V9Ci2+{chAT9F+q'
        'jN7oA3$z!Ug~waa7Xwu9##d4C*#-awxZi`27&F>}fiUr6Ehr}{9^DLMQsI3#MG5`8G&96Rc*<fUhz|oogdrhQf`ry!?P;Zq6;cSnf!SzZ8trQ<'
        'j6n*3QhUBswV5GIF9nGAo9BbTyj5vFNPx+p-Sa_z@07wP1t$n{5?uysznz<tUEJJ1oSXamc(t|b`KR3GO#T`#n$u}Y6M<FdBK&Zh#rV6ZIa?DT'
        '$(yRSWHO-&qUYfzr4J^iSrq{LIhgCwHd+eidwHW&ZqM}mJYqt<nk9MLNLmj}vPG7NMz~zFHDd?1a0kfO4d!vNWJ{T}D#A;(CWVEG-!5XKwUJ0t'
        'hO;`JDSRUDO*36+j0XtMW``FgXf8Y&GJ&_#XDRdcIwhmB)$4c(oBc|jlUsg6IN#?O6w9`er=DsVT0!vMvEz!j4GvYJjFBETHZ%rP3h9vh#uD%~'
        'sYB~gO$^b2u#8Bh;SFsW6G7+;<x>oS9uTE%6GnpkKWsF&v+)D;8UXykesx|Ea4nrn;v8QX+Ij4GyYnIQg#u)8=xc~S<W>qzKrloTX2zXy;8fsI'
        ')Xf?t5uuRq7mEPcGSDYs;a?~jToC~idPyV~7Op(^moXM{s3`)d$KZWSQq?(PX{-uJIz`kr9We7l#Kni35Ls8Ea~lbk#Z7j2&_Y&@t5#ZHu1~UB'
        'qSjFT+O-olm|DA!s;!plS6$w3FYV*-QvE~pIu2qbc!zXrbm<XzURWK^V%&GTelfTpkAS}c^AKq*ZiviTLN15op0C-iL16h`V$0G}`%)C7fs@Ol'
        'Dr+1_(q4JS$%7QjLm{$Q+H^`4gGSa>SQq_34i^TZj23ZI_Jfi<(Lo+T-;eLd_v38G)tVMeAN9ogj^wSUPr}`Hi<4lnas={zba!|A`={}HgvX;#'
        '_qV_Qd!82!Zf@WG^6u01hr#>N?WfU)^&9DD-`-w-9R2j`+qa|J0nn*r6%QTpdLDe42Fb$^10W6_fX_W7L%<;TNHh&>R_xRnqOS#47y$8m)XC7F'
        'L|+FnP||b`H+1yvi;nESfXc;-nXNYe;oWbe@$L1eUq*L>w2zL{MG1%v!gL0gm)dy%WfldF6%4Y4isF+Ng<?~he-h)g%#py&=j^(ykeAmqkxtA5'
        'lw=@1h}=rgqa8m$$A@SzS!|@NyXy)wF)%5zuDIH@&(~n}U&gni>z{ugn24tBG0#;^=i%{C41l*k!HJvt4wetk@zm(q*q<ix5DF$M9XatbbcfB2'
        '99giDSuE{vw)o<V`ef(M(0W#F{&sXXx*vbOdH3lahE@kbWaAj5g*u=xwI4iMAi%+J1@rHJ<=w3c_&EA_bNl=F<Mrq9Z`U8*{XE#*caDb`tHKvR'
        '(^M(978egWr5Fu#lGw*(GQ?GpqyKw%KmO_F=6-xPy8Z3lo6+6)=6&@eZ$AGzzWLuzqn~Rgi{fQAtUM%eHC?7IVy%&SFbR_3;>+9ygX#J#fzGC9'
        'W$|SE`S#}RyAPvnW1Hn_oG$PU@c??_CO0$tWM}Z^VE%O+ua?V2l-K~?hD$qlBj_%cW*V$7!6{}7AEd&ZVjj=Z<x#NtV5Ye&eaJ)%v=>4RtXr&s'
        'ade%j`VT2gH2!G>egpya=gQ8Fb=6(mxuq<VHZaK7S)DTZP52=h6bpXoEMw@2X4!=~*3xms5MextvnYpty1(&r3`Uz}XW(}>g3~Y_=O3D^&vMw>'
        '6wHFeeKxTEYEm-ABK{gf2skOrp<A*w&*LyHYF7Bo_2-SUWDqPK^)&7IgKGx*|CFv758R?@JX<928FxCd^L(}1^$-e*iY+F;e)Aq;cheHh8_1wB'
        '1RFc#%djY&7Y>EC2Ek;RSePhD2I#CPQ9c$S<sKrG5M>l2J~*r|{Q&X6vw^R;!rUWFlV(NkukYS(v|yY5MvFxTlA(4=m_+~qnEP}Fo{ruPV2GmU'
        'HLR^cvM3=N*eq4Xo6>AuAvI*RsAACE*9xg=%Z2}y<dSlENiwb#R%Dkiy4Z*pHX?<MY|8GNY?MOkaW<ljHX<k6h_%>=o@OIR2ETqRg}Hzf6#wDk'
        'v2duWvQ_WO&~{^=42v`Cgdteg<rPW?X?`L8APQ%ClAaIJ1*Nq6@#@h!EQ}Dm0WUavAx_dDh5Dia7&(@`$+H)cy~ylEWiMVXrVy9Q!z6#D`D-RB'
        '1USe76=A^xg0azrYD_TUf#jMos;uNn8Z9KXNE&6Cvcys&q%_n@&uSqMSM`kcX7u^~-OVRJVFQ`bF{6QvA~;K%FIz4M)|OgZh>2}$rZ#Cw2KTpR'
        '0F+z9SR1)cN_8GiP_}?RU}6MOU@}pKU>UbqlohTSn_HnNIyH!bX*C4mDI}-0bEk<1k_yh;1fS?8rFNXVh{9iVe(?Or-G|}ozZP%WNZoi9&=8}z'
        'FR8)?Nl$YojA7C;pq$d9N?5L~Pc;pF>`SHu6@f$^%=ANxr7~?{`#-;q?(R1Ou8IM7Sva-Raxu-)a7nG1olk(fgI%BWY#NjRHoeFw0cVW6Re4UB'
        'WEMypt}S=r#zmCvYkcgY6>eU=EQ;ms+RYYoY<2V-On^2v^Xe?Y-C+XrfpH3}v5Z-lvU&-6*`NV(&4Z36z+h-A-hRIMbXO);Xlv*ygR)q<{FG%7'
        'Hwi;->{hnq?-k;LHX1-;dwiTGNqP=AYon)(WiBAGEoMXaI-Rd<x6FX?@u}fZEJ<?%TIYtNgPvwVPx}n|jn&&zNuNP~P%6QU_MJ*FIXRa&tu8Q^'
        'kj$+}=2oR~eM$E!p)Ys%n|m3?giz|<6F@tZdijil>FFtlbWJ(+6vL0qDBtM*N#~S<Sv}{3uKZhOoF*-JT?+$pqjPH^w)1c5BRV;|L1bN(KUY&5'
        'f7^j+paN<a6(9u_;M-IHoreN=M^k`<Q$URZTqIVbi=+Um_t_*tr&9oRk<&?<xfQ)=w|c=OPw?qUo_0<0^o8e@yr(2jNdFT{a(Ff&bXPW^J0_Oo'
        'tP@MZj?XIUw29?KhCjLJ31+~0&o2D*>;hU{V0K}dd$G*D$Ys0NOJ*5ydX`~bvrK(A6Fo4?kVCV~VN=&GcQ@tcR#ui@iZ8Wvy}L;|=a8K<5?168'
        '+P*kRD(!x=9CE_U<WTIW<&cXE@=}9okduqbAz|-1g!V8)2`@5-@XWpVt8lLu%ptUgnF{ZkL+Ti=E^BvSS9GUj7rOHT-Bo|<P3ad%x<NY4r!RPu'
        '?3y6G*u?RDD?%?@5p3`Gk0{$3$J)?!((1o&FM^*RB0ma9Ce?q3EE;J}2s56*MtLEYHuSW|!;msRRG9cwC@PR5Of&9dA~+5;rP7Dg7-HY|x<WB8'
        'Mm&cVazUFB$b~K%QBf!L2QC`%UAG`Q6MibU#_qt~2&6eRkWy+OrxSjvj?WI3zRYd}l7&6#Gwkb3tZ}iZ$FM()=+oYBMNseLY~r+fHM<eW3%l3$'
        'wu3`=Bb+DaFm!s(IeIsOe4X^4;ayn2zTGT4)Bm0^o{^(5{@@tzbi4V5gArXM#`E4Wp3&1Wp1-2o%@^iYFNxypbQC}OcJnJ;#9@3FiqpdvarUD4'
        '0gE{7`0tY(ydGPF@QYkHy~rIygreRd{PZuNIIS)a!bRp*;-cN^1=rzO58p%)T_IfTdCbkpJBH4*Etq+IZwn?z?1JT}?`^?HX@S4Vw&0^wA^mR)'
        'K1vT-UmHBgJ&su!Y|?_&wK&K<`qF}Luah3?9(}2@wPbssd-Stp%jK@Sc%mSH?4@>%b9FQaJeUL2IN+;D)|bHnCFz?3a_@8w2wGhr2b7sx$?qJn'
        'nF9)RItP?pIiUP!OydRKh2rvM_hN_>R$}?L*rNSkyb{aSSjlR8;q5kp!&|K&zUC)gz+7}*lij6XXGh5NJ`K({{Hp}(?98jP?DekBZawQru$<=V'
        '5X_Z51h?^#M>^DsSnD%ELoO|bbYhf*|0F=6mA)24OYK|b`5qQndklNR1eh9Zg~F^^pS$~;vO}(yJtN@I?s0OdI-R1Vi~Co0T#GHHpFdgo^bOZl'
        'oR!B@<wL1b4QF2kr@0KO?8^hF@?j{ePN&SE-T5eUBgXEc&MI>=^_@DmP-pLS>a4m_XVueF70Am{XSwqUI%?}{^Zd*UAoBPp=Nuf(HB^5U;l?ik'
        ')deEo3f1N5PtbANT`;P9nVWgvQN0<}We?BF@w%eAx96t{F7l>Wg>K8Or{o++w{hpx!FQz&uSgx@rMAGy<M&S-3>mf5adJ#|TX^{gOb8?ozgg-y'
        'eIJF>?t)VX&cAJ?FWS#uGI#XxXiwBNdFX$})@JGLe5fXR@x9Fo9S!UU2Xy`WE3YErE(6&;^R19w;nR^Fw7X<v&%Y?;e@FI~XEu`_kiGL4CF?&='
        '>Ag;5S393-h1cIu^!h_~_e+UgZb_*1gRJsf60TxH7;i(&u1ysU8;=y<w_T8ww;kcywj<Qf_9rFwZ5KR?7P8ZJ!Lz8M_HP$FiynJ-lZIt2NKFg8'
        'OAFln>FRrTlb%J3Zo5g(qDqI|q`m9$HvN6CjSh69L;e#}8z4j_AVeh~?A}ARZ=Y(#{b{X#q#yV9_`ZFrXVF4*+NXLJRpkDCs%Ozd?Q@Tc`?H!B'
        'w5Kri_PNJ7w19>>`Nw&5!TTMgcSUN*gb~>&aUwK*zP`IFOQu`Dj0V)vo!TJ(ak})k|J)B($2sq_Uz2hCWtx}=_lUQD&#(Uee@SgY^#'
    ),
    'authority': (
        'c-rk<YmeKuw*4!{eC`4GeiWDw({x${X_MSZ+ItHez@R8<#;C`h%APz<(f@u)J#4+L*VuB76(A$aCbdcKz1AkVN&bE1Emr<wb$|8!-&elb=y370'
        'U5D<I2^RBUu{85_5Nyo$>U#(%N8-Eai|~`O4<Hc4KG-}cMA_B%R}chPd)(JFpiIF48t!q!p~gN$Tu?2UmNpfZL=zutUoqqP5+gu`@~OJAc`g29'
        '=HAz>*<5`u#6RC%J%#K0P(5y(NUB;cj3LU3#jqgXT`g9dZTPIWi}fna@b9b8+`G?euC!i1ueP@2^KGb}tnfq#90&kFAgJ#HX77LzfW~*8u)^(A'
        'FPCerwx%krQ2@nhA&T!vKJD}NVI3~EU+2%ONA*;d1(g8DSqK<s;nigEbzzo%RTkV&vrx1u3s3p;M|Ho@g~ZS$_OLB>l-TzGsZP9pGNFnpH=hA^'
        '88AQ1K+?JlKACV+PL5o1u}kh%Cx702orh*=)TY=3+NGDf!t2Vy>-BQEsCc<?iS@4XgUZU+;d--~KdJlTtGP=}bgDU=#D&PG_N~<SHJU>`n@8O2'
        'xJv8Hm&LX!oy4};;_C81d<EHbfm$qW5)gp&>&h#aWU*4qLq-D9*G5mAqRV_9;bvQ}p?FtXmXx-Td>xv_eX)s1q+TZ03aef$ZmfJo)tMCnB54~H'
        'zdQfNwG~vCl2Vsc!PKa&dcg7<*H)W@<@&Q#%^)ygAq(GS5qPOmBV45!PvPQ|Q;g93^=vlVs&X5gmK#*sWtzoitMs2$8DO5uK!d6bLZkdRi3crg'
        'd6F2yiLE$_DYkzJ5m;(fOtM}rojul6yFzJ0YgN_I)rK4;MLR>Li6Ix0)-^Rx+lvQrdleHlyfxS<HWXEj9hzF?hB|#OA=ODgt^cfkX^;X3;>n#?'
        'PU%4V>8Wgxk&<$eW}!gR&bdNcc7OIVZH)2W6ceC}lesK%35{N_{CZRNc64cIm1=J+TWzaNBjOvMrD_?NDz&uwZ27*S<eo?k!+<J4h%=~2h+vwK'
        '$f|_34J~n6WY4Rr>nP!qZLi8wM^u4Ongvl+wf5OEyz;EvwL%!3S{5Ynoz21eOtEKlz~P~i)O$40w#Y%B1(JLgm0k%XR5bV<LZSnXg=DDFbFeMZ'
        '>>5CVSOfV(EKn1@b1dumn=nyL&`=UlqF{s>JWR4s2;NAeR#$3y5+cYenGhjZOLdTOagfXe0tea3`u5-eA3*?FiE$8PhbRS0UdtJfVo}2ikW<uv'
        '`_NKFEwV!aVI6i;1`dKVle7kXp@r&Zd}TSEtpHF9_XiLXLV{~B5TcyrW(&=78eI)zT);y(g%SQI+cQK=3IjDmo^24sGzy4dC@>l-sf5smamE<6'
        'o{jRjR-Q6UYalF8D(P`i=ou0qna$p-?hjheJKIe~){_Cv{Xy?wm%>A-Pv9p`bQY|=dfyy1`Q~1C-`qRoR~xhIfAX@=<n8dHnoc7((R$TM7G6;H'
        'V!S5Toa`JRPOFmEFc}l6qbFgN(48IAIEe-Om94HvQ(05Czn8oe^KwtmODrZ(&&zG{ZorMSRZ?=6kODB9vX-%Zld6N|>x$}ewq!C)n$JQ;Qlqqn'
        'kyoF^UTVz&#{|Y{q)v4rDNVJzP-zd=JgXI+WuQ6LXv+k$QD-rc2bGdwUaNI9gUw!!=XgnP5T%C{14CZd@>q(Rrez2oY&$AwUE^TEvKT3$Hi6a<'
        'V@rqB(*{{x<0>!`E2NR~nIVV^Wxr5{5atIS6CQ@v(0wG7slrH`|DPsYndSV!mf8aNgZbjL!l#Nmm4pet5YTuX_`3DQlYs(YVBjfhf55Y1Y9B#s'
        'O^|4JN3Bm~H43|4BS$P?-2M-lZ@p#fJ~3ne1)SJVh}jN3N1QTaKS}pLAtazSCG%}MV!t;i5}g7P*($T7lUi-nWqW=AIs0%OBIBOOqzA}IY&Y>`'
        'J6bG$4)e9N`?$M_Q?bH}il2dsUtX+g<$fwkZz_Ij^L_o(F)kU&AAs|?kl|K4xErI3E-GcAJ=1n?R{gYbZGOn=oAo?cJlLQSPrQUAOO$B7)J=^*'
        'lK+v(<`$*Hz>f?k$q$S8<(eGMPrLjq#nOPW*p^5}laoeEv^&r-Cmxc|=0lmbR)$l%$?8ESKhq*V1TNR*x?D%Qu6Az0;!)ij&pCO!?h|v<Zkw&Y'
        'es&Jz$J-Ad?*4c?e*@tB_U*^JKmNT+9?jm}z5e<2+nZlzZ*K42-u|-tBKqx5cQ?P@{_xvRKi%HVtUI-R-dsD!>+9_E!rwkzLkozr2kXy0Y_BZ_'
        '*`I_9-^7odIM?7y>MP8w<M*hx*WP{jWwx;{Y1D_icJA9}6`FrpS8lUjn*8g3dHwtC{O;!M&$l0DQ5l_27jA8~eh~HGlBZ_n+h+#&&MTP30~P5n'
        '4G7r&Y4S@5qi4<u-2cw(o~8LEDRro}`oTVlL3$Rtk)B60f3O9=2DAJ1K9^l_-NQH=+bJ^calUBpZ)~mqJioiW`SFjL4srB8B3;s`AHKO}GwZj1'
        'vNx{lJ9~Qgx>;zooO_Gy=Gs2Ee^#N(o(JwSNhOEI){$O6nd{~Hv#ZokX5}hcE%UFxyZvzcasK|@>$e|m(<<K&&1PeB3zUy-*M9bBtOM*{KimHI'
        'zmnqSGx+uP*LQb+%zwRkKmYyam)Aee_Vdo0YY0WE3s%xdC^r_jxuzIHFjL#Dd3@Sl!+e&v|M&Xi{D*h%KF&Yf-u?di)$ND*yEpltyn6rJ{N4Y)'
        'z5TIJW#Q&2ZdMu~`)TnMsfaO@soA~1y<UG_8Gp9e-ED1Qqq}VOX#W20-A}K7xh+?=etMoq1ANzTW=rBaH%s%$EbW)G)tC9^`RQpLZjEohwja&P'
        'wV?a(q!<3~qg9IK+OxUZKE-OYjD|;TozIqv^30EPNUZdXiJ5VOHMSjHVe<Ne(khz&aBKC*8q{CUW~Gfw?(A;Yf0-r2tWK6>4*nX=((%5ilW{Fs'
        'b=GNZ>@tVBdI&c6o7l*0G2Q>0uNzxu%lOW!oeAx2u$d=6y5HR;sI`Bv^tbM}zVV*#Gc~c^eA!qFaJf8PyAfOcbsj{Iss(;^^L{TZn)&NTwTMdo'
        ';9g_P|0x<Wp1Cp8&2qi9zj3$sW|a(9yAs+5X~LQszj^h>n(qEhIC(*gjDf9V2YfLUMcu+{ri}H-h(yM^j+|I<78nT+vH(*F5JpI7L6B!O_qgW+'
        '>PzE$f(l3_A_`Rt^6}=wo4pidU*2%NjxjP&P6)mBt^Fk`9b>2S?q;@$!mm42+hJt-1np5XlNj!w#={CxMdlynDm2lxG}q|Oss3g1McL<>oMGW%'
        'F7NDzHg!bPIznk3naH`Xs-p-|`_&PytRpnIjz~=%;bC=Tx!|{7GiJ^#18x3v_LwSEUf8^L#bCRypBRec+6e+%vyN6Uo<;P6yjd75)qQk7i^h|p'
        ';%}ZGjf27v*e~oK82>@h&myExUtm9y_)8l9Veuax{}J&YnPih@m*fXg@)sw6<E#P;2eF|7$f%DX)Cyq*5k%DIR1t!O;Z$&~7{>;1EesI`8LS!S'
        '8XGQ+Vhm7GB(ztz??1kN_tv7Yw#4WhqnQaqdl$VvTXVj@tEpWL5mv6vs7`9Q;Nx8u0C}ky3oX}5sMgJCg-xN)I%3Fn7-w$mEaP8kH&zrs+&OG+'
        'fF>=}Ec6$76WA;)Iqj4?A|6XBFjf;dP)#!Laq7ZSeNo9plPggl0`vcBv}vE~UaK@$T2PN;0X5)KQNpw)+z{(=a)|{qR2dH|9C*;<L@>;J4y5hq'
        '2L^JX>&*6le!Knfao^w~ZE(lJQ9V7a7cmWI#9Erwy>;Dfy?#>5g`WY~=tJxhP(r91l&6SrVyw>w3!`1Iatx*X8TK8sg4KhU>0{oUy1K@kvwHix'
        '?f>lSOcuQaH^F49&sI)aYb188GpwG0UNWnIT>YTJd+WjATD*P#?(K)HV+Bf0mur;uljEnDL0lgUxVC#X8GX+=E?_T#CAP=M#daIrTbwoFr`X9{'
        'TVh);uif9p>e;ko1_=98Lsu+`xB=|Ap|{cF*y!<?M!&E1dMX*y=sQsfBzSBpfoL$7IH@McB`8)a6suLHT~DcA8T6$Ne-kZ(5Fw1+cg(sSLY$s)'
        'ARbORs4e9bDTelBloy&lX-zqh6gekw&tH;ps-&PrDYVTuJhl|9%)gP2sO`}!gcn8m>v>@|FWWE`u7GHA1yJe=(6TE4j^hHz-Y!6A3MjY$lf-H;'
        'Nf$tj-kU^VxC<aA*`36(TH#5n)d@)+!Qmv2+mbv!alev|MDhrY-?2p9*#zMxHo*-YOLWwZB_jP<MGWg$PSX6*q&t{C8J%6|aCWg$O^{tktX?Em'
        'FEnlSIwi}n;VeVivP>}?40mK1)RkqrbzR%cZu0$9R?IKynwGY+o2WI1H1<eH$|1OZa1!O-`(hk2pl8w*I|>{!Nh8m^Ffwv9DGmun=MX$X4<(o+'
        'htOEP=vk=O2{{Ch&{LspIi!f;Vp_q0ZP6X0CUmDMx{L9~o1*n2?I0Z|-50ngyDCUegE%gs2&04|n9=8tFe$ZTq3K#l_1_nZ;3XGJt`w3{{$H0t'
        'BSjG+S~94G3?MgwRFVb(CSD*Q@-P#a0fC4j)Psmo7$}UnXQ?rOo+sNvF-==MffY2NU<5SLK_kqHPJPEgBib|t(c0n1ywr9bqY+RwHJ}VNpy3Wb'
        '7X8`5;L}7SpxErum}Xz}#3~1iMl}0wjy@iJDgw*FY~rLkn`i`dV)ZJA9dwOGI1c9!Fr0IGM<ej_bpHu#!us8GGjHwwkBspI^~U(lHr{Hw`NYNu'
        'CW-NMbc`o>IL6a6nr@z$TAdQb$#4|!J>7h!gE)jXp*Ze7h;tCdI}GBG{_9CPkH;1ue3ApFlZ+Tb;}80f;R{gE2?u=wzZSw-tX6DPwTj;NZA1)_'
        '!z)o-X^RjJvY^Eh2w$yNrZo)8rm<|6!XQXtkRLgAl7ikyhz1T=oQ2BrDIg&RqdT({4n{&J)oG9rf(B=n$7;n#RIB8D-v$y=bN~tC(l#O??}3E0'
        'G479_9tr!$`*pU20ur8u%1#3b@#rxcba<Sflj`_L800Te2Z$opE-{jJm0$af;9^s>U#ZZI@F@DgBX5F7QG!Q^kByI_KR)7Nedcr0V1E)YN#*D;'
        'DTl+P&EwRgpKem9fR8fPF8MMeGE|&9Ff!03gw0lP1tQ8Gh{#|QBFZu%9vKiB>JNxrEujF2=b^HbKtis^MnZ;%BcYXQijiYUh@qPF;Pfe>kc_aO'
        '4M?yMfCDo@>f4ylXS8uA8Bm(gKRS^2pAG74$i<+o^RT!{Ah|-LBl+;@AScxnkvxe8^e#wVgXClEOja8Wj0#BZeIrQTIGF`u3CYosk(~FR&FXB('
        'MI=89i$jw@ay>ed^AV=A^fZw?iTTqPB(Fwtjz&Q8)-kraaNG($PbBA!lW}ktWGiI~<;Naw<^!hV^gt*-3zNf>fbu|$4&@`v$3>H2(}VIP&ep#`'
        'c@310u;B)59cb%Uub?~jCXIukym8_X?jmhTisa<jNIqcVu&W^#k^C$yj!Xf`2^oE$oDZKebW%+b$&=kx%mvA7_I(E<AbIP(lgxp|)^LhD^p%lZ'
        'G){OzQd;GFY$O-`XFNL_auLbT!s4cZ<klk?8Og=)DNiTW6p=hxj}u&wyavg~nDT7BgHdpf8>&|zdGnMfEp3@ikB#L0r#w3wauLbT!s6&8kX*yj'
        'k$m`+r;}=mNS>@Gg5Uz>HBdgroF{7u<s}3@iye?EpuBm`lbzftm;L8FJ6m!Q%Fn~(CgGJ+V9HpIhCsO-KIiF#>aru@k&rxD4+Y@`$*YlEjxp!S'
        '+ah_}z3kAmhgW3toF^|K`LUgH*?-Ejt05PG{5&jf5>7c~Y;31o4xjRLQcck*PnK>$bb<03C?8|aQ?!M0bnLTi(93K~D*2%U>rm6Cq->n?*`#Q7'
        'RNPTSDV-W?`Df`V{pU*xQgv)>^SQC2#Io?%9VTlP{du-4%od6EJn+y=f@tOFVWJQWKQ-2gHASXP)&xR)VcMFLVZjJT!$R4XYKxJfY;3AM&Qt~j'
        'q!G|}>u}i)(9zKWo%RQGIWSiAJj_l{0?@q|0CYAS(7j0lI!cxXLUIB0IzZ<mob?Ub0y_CNHfDvO`8a2A+VgcFko~vUrY~{s=4E^BijAy2Iy#g?'
        'FnoV)E7s%>+`R0sT>^3lhi|am`=rgjF-GXbI1W+M4%?&@V?>U8P6CAek4o!o$c?98PSoPaB#=A^#z*quXRA4}CV%YZ1<A`uKEfeuz0bRR@!5=*'
        'nV5!<H6c0e9%3{)lJovZ-qnyB&r7%<dBe#BM2?T-Vla|Bu_lP*`Q7I)NM1&AIULE`28-4Xjvp&nl#hhu2s9yiIapL48_5yujpUsTx$(S*iCUbT'
        '1d_AS&wGFf4M%b|$<xd7yXRk!yoBTk4@dI0!J;K3?K-;BJBW11=t@OE4Me1P@^LZ5X!LWBE5)EiF|^G%Jh~Va=RjA4IvqzAUX<mp=Y`q4Y}-_k'
        'y=WqPUK)S{M<@IKQz@OXzVS$t%T!7OtIF}aZFu-piW6&sWS>6@;zIT%vd1G#rL+wvE=_^6vAb<Yno7ZqQz@cHh|}0mj{DE0bhhNi(^n>Ha(WU_'
        '?!5q%51&hMVoear^M_bmpu7y_Bh00=4Oa!SfSvM8qnmK!T*@w5RgUMBn=gxPwRj&szRQ{NZWbl9-46@fE@g%JmNBIXFJ9&0LKOQ(z6or;#*a!D'
        'b$?KFoA3PWOODzylI$OJ>kSLKJ(JMLNt~ih{n3{zLIQ>d-TISUuZWUe+#$UL-PW)Yfg=Rn!nQ%T^c;h=ss^pBhjC!VV&jk%DGynp9?JwF!9_7T'
        '4JVE!25Gf&@;I{4qAVSU6Z;5~XKhj%T@6i?=Wx<4`bVU3yI=&nk6Mnsnuqk?FSs+S6djB6fd5H277UEPnuiSEG1!SUMaLpJQvkAyV^QN+&=K|w'
        'Mr{xBfb1NXXXaUh!qS@mZma=Yvj#<ttbs}+q(`6YqPRC}bcT!~YYeyTc0*a;0&9@*7Y<P}oHfWK7Y?ChMH=Lj)~u7V1|5Ml+MXE#`GK&)!54ga'
        ')?h`}u=TdquH#it8>j_s{BZN?&Fi;6XJ5s4y!5;=e!c^h=!x=qptOgmV1Z^vGNx^J%jZ7yA@cwt0TqA-0oNYkR;dK_mFEkO2qBSHygh|AFMHjc'
        'lLE^Ww%gz?R|_xJ0iyj!Ry*TZk;;Yx&P%wd`v!=C2TqF8gc+UE*zgfnC)N}xEm@ieMU#f1sc6_Ksf~>>(%N=eEEMP1A*#T6*4$MgrLM}cxA}x@'
        'Kv$)!Q5W%jn$|bTjXs$##>e#$x+?x84>v@~LOm!atyw3<^D(+AZ5PKvdE#B0`B*b&jFsn#to|;S1LkLNkDV=9^UO(kneM&=fp^Am9D?aTgVGsY'
        'iUc!F7}z(!1jocU#N!jq@R<}R))a{*J#<3F8iuE>VW%V<KE{kn>jPiZNTC||m>q~J!r^f2Pz~HCE`g)5LpAz|fnOw4qn|8f{7{WPt^jX5-wm<T'
        '2T}0;2fTI0{h|vnO@N-{bQs6u@4m!`AMxhInj-b5$CP-J)~u6K{s?Ehq1Gn@c`e5b(Uisv^V4Bmb`PRJ{emb&<IxC+pFW5}^gkJ)Gh`H5W4LYq'
        '*91{;IzDTN;U^<Fv8Kox>6sgP(wcQj)(|6{jDT7nLZk~Y&ChhHnP@y20qvFz^V8vZ|AP@a8*>rQ&%^4bf#*_>kLSY=MsQ+H5zo^jH~b5p*WvjX'
        '2P3pT>Bj#?mJW;N2(go{9o`>9-C^x;gey&$Q8mUUL8qhjU}1y}jI_y<goj2yk0S=^e#GC4$$}4$ejY~<a!5sjtQe>u25b@ob`XOeQjz0`!CI-v'
        'ab)3#Rb+HQetP}(=9jDxnPV|+ZlBC11BoC5i68@s9m*&VZOoT50$eB|8pjCiI}UBkcN{TbtBv`NBMUmbG2d|n!G}~NX9T1m1|G*65g><D<Tzr`'
        'Rw{BFS=eC}8C{S9Kp~LXKyn~Jy}$YJA)B+Xj-Xpo@w|Olhl}mkS-QBwpFgSl=tYm}>1naL-z09J`LdmFJ}<WV!JS+3@72{m{|^;W+>`'
    ),
}


def fixture(case="authority"):
    value = json.loads(zlib.decompress(base64.b85decode(_FIXTURES[case])))
    return value["stdout"].splitlines(), value["binding"]


def field(line, key, value):
    return re.sub(r"(?<= )" + re.escape(key) + r"=[^ ]+", key + "=" + str(value), line)


def encoded(lines):
    return ("\n".join(lines) + "\n").encode("ascii")


def resequence(lines):
    sequence = 0
    for i, line in enumerate(lines):
        if line.startswith("TESSRYN_K02_SERVICE_"):
            lines[i] = field(line, "sequence", sequence)
            sequence += 1
    return lines


class RegionTraceTests(unittest.TestCase):
    def accepted(self, lines, binding, case="authority"):
        return parse_transcript(case, encoded(lines), 33, b"", binding)

    def rejected(self, lines, binding, case="authority"):
        with self.assertRaises(ValueError):
            self.accepted(lines, binding, case)

    def test_complete_three_shapes_and_actual_continuation_counts(self):
        for case, requests, traps, records, resumes in (
                ("sharing", 14, 15, 105, [11, 4]),
                ("revocation", 14, 15, 104, [11, 4]),
                ("authority", 38, 38, 209, [29, 9])):
            with self.subTest(case=case):
                lines, binding = fixture(case)
                result = self.accepted(lines, binding, case)
                self.assertEqual((result["requests"], result["traps"], result["service_records"], result["task_resumes"]),
                                 (requests, traps, records, resumes))
                self.assertEqual(result["context_switches"], 4)
                self.assertEqual(result["domains"][0]["charged"], 0)
                self.assertIn("b:read_confirmed", result["stages"])
                self.assertNotEqual(*result["task_fp_sha256"])
                self.assertEqual(result, self.accepted(lines, binding, case))

    def test_bounded_real_firmware_retry_shape(self):
        lines, binding = fixture("sharing")
        start = next(i for i, line in enumerate(lines) if line.startswith("TESSRYN_K01_LIVE_RANGES "))
        end = lines.index("TESSRYN_K01_EXIT_BOOT_SERVICES_OK")
        block = lines[start:end]
        retried = lines[:end] + ["TESSRYN_K01_EXIT_BOOT_SERVICES_RETRY"] + [field(line, "attempt", 2) for line in block] + lines[end:]
        self.assertEqual(self.accepted(retried, binding, "sharing")["traps"], 15)
        self.rejected([field(line, "attempt", 3) if "attempt=2" in line else line for line in retried], binding, "sharing")
        prefix = lines[:start]
        for attempt in range(1, 10):
            prefix += [field(line, "attempt", attempt) for line in block] + ["TESSRYN_K01_EXIT_BOOT_SERVICES_RETRY"]
        self.rejected(prefix + lines[end:], binding, "sharing")

    def test_reserved_scratch_is_a_stable_nonzero_low_profile_page(self):
        lines, binding = fixture("sharing")
        i = next(i for i, line in enumerate(lines) if line.startswith("TESSRYN_K01_LIVE_RANGES "))
        for value in ("0x0", "0x100000000", "0x100001", "0xdfdb000", "0xe0f6000", "0x80000000"):
            altered = lines.copy(); altered[i] = field(lines[i], "scratch", value)
            with self.subTest(scratch=value): self.rejected(altered, binding, "sharing")
        end = lines.index("TESSRYN_K01_EXIT_BOOT_SERVICES_OK")
        block = [field(line, "attempt", 2) for line in lines[i:end]]
        block[0] = field(block[0], "scratch", "0x101000")
        self.rejected(lines[:end] + ["TESSRYN_K01_EXIT_BOOT_SERVICES_RETRY"] + block + lines[end:], binding, "sharing")

    def test_exit_stderr_framing_and_byte_bounds(self):
        lines, binding = fixture("sharing")
        data = encoded(lines)
        for rc, stderr, stream in ((0, b"", data), (True, b"", data), (33, b"warning", data),
                                   (33, b"", data[:-1]), (33, b"", data + b"\n"),
                                   (33, b"", data.replace(b"sequence=0", b"sequence=00")),
                                   (33, b"", data + b"x" * (1 << 20)),
                                   (33, b"", data.replace(b"version=1", b"version=1\r"))):
            with self.subTest(rc=rc, stream_size=len(stream)), self.assertRaises(ValueError):
                parse_transcript("sharing", stream, rc, stderr, binding)

    def test_unknown_fatal_mixed_and_trailing_markers_cannot_hide(self):
        lines, binding = fixture()
        for marker in ("TESSRYN_K01_EXCEPTION_UNKNOWN", "TESSRYN_K01_FAIL reason=test",
                       "TESSRYN_K01_PANIC bounded", "TESSRYN_K02_PASS", "TESSRYN_K02_SERVICE_UNKNOWN sequence=0",
                       "TESSRYN_K02_BENCH_BEGIN", "TESSRYN_K01_EXCEPTION vector=6"):
            for position in (0, 10, len(lines)):
                with self.subTest(marker=marker, position=position):
                    altered = lines[:position] + [marker] + lines[position:]
                    self.rejected(resequence(altered), binding)

    def test_exact_fields_duplicates_sequence_and_whitespace(self):
        lines, binding = fixture()
        i = next(i for i, l in enumerate(lines) if "_RESPONSE " in l)
        for changed in (lines[i] + " extra=0", lines[i] + " status=0",
                        lines[i].replace(" caller=1", ""), field(lines[i], "sequence", 100),
                        lines[i].replace(" status=", "  status=")):
            with self.subTest(changed=changed):
                altered = lines.copy(); altered[i] = changed
                self.rejected(altered, binding)

    def test_actual_exception_is_adjacent_and_matches_every_raw_field(self):
        lines, binding = fixture()
        raw = next(i for i, l in enumerate(lines) if l.startswith("TESSRYN_K01_EXCEPTION "))
        for key, value in (("vector", 6), ("error", 1), ("rip", "0x1000000de"), ("cs", "0x10"),
                           ("rflags", "0x246"), ("rsp", "0x100003000"), ("cr2", 1)):
            with self.subTest(key=key):
                altered = lines.copy(); altered[raw] = field(altered[raw], key, value)
                self.rejected(altered, binding)
        for altered in (lines[:raw] + lines[raw + 1:], lines[:raw] + [lines[raw]] + lines[raw:],
                        lines[:raw + 1] + ["TESSRYN_K01_EXIT_BOOT_SERVICES_OK"] + lines[raw + 1:]):
            self.rejected(resequence(altered), binding)

    def test_coherently_rebound_raw_frame_still_requires_compiled_stage(self):
        lines, binding = fixture()
        i = next(i for i, l in enumerate(lines) if l.startswith("TESSRYN_K01_EXCEPTION "))
        for key, value in (("rip", "0x1000000de"), ("vector", 6), ("cs", "0x13"),
                           ("error", 7), ("rsp", "0x100002ff8"), ("rflags", "0x246")):
            altered = lines.copy()
            altered[i], altered[i + 1] = field(lines[i], key, value), field(lines[i + 1], key, value)
            with self.subTest(key=key): self.rejected(altered, binding)

    def test_first_entry_and_every_resumed_register_are_bound(self):
        lines, binding = fixture()
        indices = [i for i, l in enumerate(lines) if "_RESUME " in l]
        for i in (indices[0], indices[1], indices[5], indices[-1]):
            for key in [f"r{n}" for n in range(15)] + ["rip", "rsp", "cs", "ss", "rflags", "first", "resumes", "root", "fp_sha256"]:
                changed = "f" * 64 if key == "fp_sha256" else "0xffffffffffffffff"
                altered = lines.copy(); altered[i] = field(altered[i], key, changed)
                with self.subTest(index=i, key=key): self.rejected(altered, binding)

    def test_trap_context_gpr_fp_and_stack_cannot_be_kernel_status_only(self):
        lines, binding = fixture()
        i = next(i for i, l in enumerate(lines) if "_TRAP " in l)
        for key in [f"r{n}" for n in range(15)] + ["root", "frame", "trap_start", "trap_end", "request_counter", "rdi", "rsi", "ss", "fp_sha256"]:
            altered = lines.copy(); altered[i] = field(altered[i], key, "f" * 64 if key == "fp_sha256" else "0xffffffffffffffff")
            with self.subTest(key=key): self.rejected(altered, binding)
        # Rebind every A trap/resume FP hash coherently to B's state: peer separation is still required.
        a, b = "c7ac85b7381c079a546cc47e4e6079386e5aeb3a3fb1b748636d709f66fe178c", "ca5224c961c89f17ef9a95ff34bf812b368360824a45b12651fa337b1f4f1bb9"
        self.rejected([line.replace(a, b) for line in lines], binding)

    def test_every_copied_request_byte_and_actual_pointer_are_bound(self):
        lines, binding = fixture()
        i = next(i for i, l in enumerate(lines) if "_REQUEST " in l)
        original = bytes.fromhex(lines[i].split(" bytes=")[1])
        for byte in range(96):
            changed = bytearray(original); changed[byte] ^= 1
            altered = lines.copy(); altered[i] = field(altered[i], "bytes", changed.hex())
            with self.subTest(byte=byte): self.rejected(altered, binding)
        for i, line in enumerate(lines):
            if "_REQUEST " not in line: continue
            for key, value in (("caller", 3), ("request_id", 0), ("pointer", "0x10000fff0"), ("length", 4096), ("valid", 2)):
                altered = lines.copy(); altered[i] = field(line, key, value)
                with self.subTest(index=i, key=key): self.rejected(altered, binding)
        bad = next(i for i, l in enumerate(lines) if "_REQUEST " in l and " valid=0 " in l)
        altered = lines.copy(); altered[bad] = field(altered[bad], "bytes", original.hex())
        self.rejected(altered, binding)

    def test_denials_and_outputs_cannot_be_changed_with_valid_request_left(self):
        lines, binding = fixture()
        for i, line in enumerate(lines):
            if "_RESPONSE " not in line: continue
            for key, value in (("status", 15), ("value", "0x999"), ("cap_domain", 3), ("opcode", 0), ("charged", 0), ("committed", 0), ("reserved", 1), ("control", "yield")):
                if f" {key}={value}" in line: continue
                altered = lines.copy(); altered[i] = field(line, key, value)
                with self.subTest(index=i, key=key): self.rejected(altered, binding)
            status = re.search(r" status=([0-9]+)", line).group(1)
            if status != "0":
                altered = lines.copy(); altered[i] = field(line, "status", 0)
                with self.subTest(false_success=i): self.rejected(altered, binding)

    def test_all_retirement_phases_and_failed_install_rollback_are_required(self):
        lines, binding = fixture()
        for i, line in enumerate(lines):
            if "_MAP_EVENT " not in line: continue
            with self.subTest(removed=i): self.rejected(resequence(lines[:i] + lines[i + 1:]), binding)
            for key, value in (("domain", 3), ("frame", "0x1000"), ("va", "0x100009000"),
                               ("lease_slot", 31), ("lease_generation", 99), ("charged", 0)):
                if f" {key}={value}" in line: continue
                altered = lines.copy(); altered[i] = field(line, key, value)
                with self.subTest(index=i, key=key): self.rejected(altered, binding)
        i = next(i for i, l in enumerate(lines) if " phase=rollback " in l)
        altered = lines.copy(); altered.insert(i, field(lines[i], "phase", "clear"))
        self.rejected(resequence(altered), binding)
        i = next(i for i, l in enumerate(lines) if " phase=clear " in l)
        altered = lines.copy(); altered[i], altered[i + 1] = altered[i + 1], altered[i]
        self.rejected(resequence(altered), binding)

    def test_whole_payload_reuse_quiescence_and_zero_accounting(self):
        for case in ("sharing", "revocation", "authority"):
            lines, binding = fixture(case)
            for i, line in enumerate(lines):
                if "_BACKING " in line:
                    altered = lines.copy(); altered[i] = field(line, "sha256", "0" * 64)
                    with self.subTest(case=case, payload=i): self.rejected(altered, binding, case)
                if "_FINAL " in line or "_PASS " in line:
                    for key in ("charged", "committed", "reserved", "leaves", "allocated_pages", "mappings", "context_switches"):
                        if " " + key + "=" not in line: continue
                        altered = lines.copy(); altered[i] = field(line, key, 99)
                        with self.subTest(case=case, final=i, key=key): self.rejected(altered, binding, case)
            stop = next(i for i, l in enumerate(lines) if "_STOP " in l)
            resume = next(l for l in lines if "_RESUME " in l and " task=1 " in l)
            self.rejected(resequence(lines[:stop + 1] + [resume] + lines[stop + 1:]), binding, case)

    def test_private_task_roots_and_backings_cannot_alias(self):
        lines, binding = fixture()
        t = [line for line in lines if "_TASK " in line]
        root_a = re.search(r" root=([^ ]+)", t[0]).group(1)
        root_b = re.search(r" root=([^ ]+)", t[1]).group(1)
        self.rejected([line.replace(" root=" + root_b, " root=" + root_a) for line in lines], binding)
        altered = [line.replace("request_physical=0x4000", "request_physical=0x2000").replace("frame=0x4000", "frame=0x2000") for line in lines]
        self.rejected(altered, binding)

    def test_coherent_frame_and_root_rebinding_cannot_escape_profile_ownership(self):
        lines, binding = fixture("sharing")
        for replacement in ("frame=0xf0000000", "frame=0x10000000"):
            altered = [line.replace("frame=0x5000", replacement) for line in lines]
            with self.subTest(frame=replacement): self.rejected(altered, binding, "sharing")
        # Both contain the kernel's original paging object, whose root is0xe049000.
        for replacement in ("root=0xe048000", "root=0xe04a000"):
            altered = [line.replace("root=0xdffa000", replacement) for line in lines]
            with self.subTest(root=replacement): self.rejected(altered, binding, "sharing")

    def test_compiled_binding_cannot_be_omitted_or_substituted(self):
        lines, binding = fixture()
        for action in ("descriptor", "offset", "instruction", "program", "header"):
            changed = copy.deepcopy(binding)
            if action == "descriptor": changed["descriptor"]["sha256"] = "0" * 64
            elif action == "offset": changed["programs"]["a"]["offsets"]["region_a_map_trap"] += 1
            elif action == "instruction": changed["programs"]["b"]["instruction_bytes"]["region_b_write_authority_trap"] = "00" * 16
            elif action == "program": changed["programs"]["b"]["efi_rva"] = changed["programs"]["a"]["efi_rva"]
            else: changed.pop("kernel_header_hex")
            with self.subTest(action=action): self.rejected(lines, changed)


if __name__ == "__main__":
    unittest.main()
