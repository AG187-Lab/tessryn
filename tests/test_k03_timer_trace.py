"""Adversarial unit fixtures derived from dirty diagnostic5 guest captures.

These portable original marker bytes and compiled bindings exercise the offline
checker. They are self-contained tests, not clean-source execution receipts or
capture authentication. Final qualification must use newly preregistered runs.
"""
import base64
import copy
import json
import re
import unittest
import zlib

from tools.k03_timer_trace import parse_transcript

_FIXTURES = {
    'preemption': (
        'c-rk<YmeKwlKm@2KHmlSeq5kG^v(3l29wt&nc2O-0)`$`$CysL$988XdvX8!mL8NSiLxnMmXk?4NZY0*szg<>&MA_`e?5y=_vz~X'
        '_SxV6^(-~pWV3qMtvC5MldYE7>dq|JS++I1XMe|xVWR$4{IK~P<pok=^0#N(j}hVG+25a;IOUk6DorvaQj|oD)0ih2Wt1m6W=Whx'
        'l2e&T%#hZYMTBIT6bv(gVw60Cx>o;ZmhqRJ*%lZ4_uroVW;XZcZu!wfsoB8WpKu|T@<=L#5Ju&Tp}nsIKL@{xYvwP5vp7Nqp%`u?'
        'NePY>!Ys)@aVC_|k`g45Bq9?M{$i05Bq+Qa_?Jlr--zIF43S(I_@?u}jIoTvnIeVr82oNXAv#Bl=kJ0kf%vd|8T=;%{=|sn(!n=_'
        'NFg~X-^&+8nJn85w_B<HT7M|d5}gZ)ehXt?Q%Cuss&}RCw~*h5OQ(3zqHcc9OHBA8MuK)oC9Bp>HA%`Rh3g}#C%0Gi?Zbuo2<RJz'
        'T8j#dqP%{b#X+=s;<Tklemi4OpIcl0(iElnyR!AE@?EII^(A?ITqvFiQQ8u7?f|>Dk}Dhwkq_$OA^|I-sP)`ww>}b3A3;yAr`OYK'
        'w%4;77OXx+w<eCZ4one%Q64ty+fDRon**81k7g*%u}cGH1Xb*B&sO)_-R3dbt=9JzhWzW<#@y!Lqh)ID%x$zY%iSh=$Z?2LG|MqT'
        'rg#*UeTGqK)hRIza@OaXKUX{7dAjOyjEZCH#@+L>XmtmtfNzfvG)Z&H>OQ(#MoF@Myx#%1^IbMY_Oe+8YTDv{iXObu=3QhdZPjzP'
        'Pul=YD^H0rVk*|mFv&P4oN@~9j47&<sC&x#{_YEW7`SMLZPQ}yzv!LGRls*@eVbU7pJLTMb^G|qqz4+ydO@Rvx0c8I0m*S<Ph`w@'
        ';vbvUE{Z`d2Wz0QZE$c^q^@DN`UGeg9`$;23*xUfzr%R|KatUjRc*v6PGfimSqTga9kJ(aA6EBEbDuvec#yI}wJPEE6G&djo21>d'
        'w!3Jv%cay=mQa=|Zc@oJl}jC4Wdb#M2H?H4w!KEgIQCnKq^M^G7&CfU(S^`nO(q2QRFyD&NEZRC3@V$TGDMp=mjmho_J2qpC=&h$'
        '&NT5oQBYU^BLi~wZ<ns6KvgmoAxwA#IzYI@h^NXxkCbr}qZp@zrbK3%XA!3GOKgAw8Tg}QLOXN~n2><#V}ExGP}Sv*0ITv=-Phg5'
        '!(ArX*JZ}zyUcj7yA#%a!HRmFdOW_nD^FP_>-%iA$yLQ?@^z;ncy&?Ut|6q)%4)x2P1)^w;#?;N`W>F19@lN0R*l#`eXzqyqS~?0'
        'sxyh}E+ii6c%-(U((36r9Z&4-cskvUBw5uN`8%GLIx!`C`l7V<Dg+_2_rwY3haM@#GUS<2jrKki*1A&b7m9t&N+tET8|b5J{So*H'
        '4Bka)OtJ);-9RS=YRg$>NK7;rB8sGemQDy@s@P~vGE7m%m5@v-pY{JczrZeCKjx3=!_E8m@BaCE`7^@Ho7W%S{qukCtD?o5cQ1Z='
        '@%sAZ;^&)puWw$~KNQFQ`0o1E%|Cwm@yDBY3lM$xxV_37_{-vtRl56lg^5Cok7jlIad!nz9}d~9Qd1V^K=2CvX_aCDo#m%!cNO1m'
        '{#<OK-!3|utNbzj5pB$Wz$4qP?@ashFJJt6vwU~``lp-sivnGi?FZGSS(58(RSJy_Wd<d=dE|m7ztu+?l!>OaIuhfeEPsH_ai%V_'
        '^;Kskn`oDOgp!hvE;hN=d@{?AaN}2Kal3A6sc$zgEUQt7n!LDuYj3Zi)qh&PySe`1pNnKei|f%G8!QU1v%L}vaBiRBL*73x9zK5A'
        't`hLD@oKldf`Z$}Xp>hjv;1YMM&1}`qh$SHuI|=<<c<2-+~*A)-L)_O?&kf?hvnNhFJ6CuM;oOn7{wN9%c7KWLKdIQ?&CVWdITr&'
        'AJy%)D|mJD>dm`<E?-^0UH*Fg^2HB}CStk0!dO{d07(m>9^g4`uQ-K%Xc6sp=F`LO3b(7g`JWdbmj8J3=EL&+&AVS;JimFreDibr'
        'kmqlIS-$!2*Ec_OnryRuC?6}&2z*;T6e?mUH__rY-CeE!xHsuyRe##S%@&{B>dEr$yEi|+czM%r?BwBbS#%axcma2kcNur)v$=yG'
        '7x#ZIw~r4G>&?!j@H2ch_xTgdzdR(XwEhZ8akq}4R_HVCw|7zgT%gStcM+G)LCJ=J^g^hG$)Mwa=a}D2TYu>C!;4op@0S0#0WAV^'
        '`u)+|Cni5Rx4H*taA;qse(~9Cwz-{wC>0I6B8yFa{B~D%7gt*NYPL;L*Nt0^kZo_brG>*i=6|<ew$NaA<tNZNvw@G<c3B;CTYsv^'
        'VpDLJ?($<(6F=TM&9L77xdrvlYk9cJQEKvKnH5Doai70@^Ze&VShCozA2;yf<Ad1=W;>(IlpYP5=^=_&cdOkODAh^>m4JUD0!O=e'
        'Fq_pnU1p%h)|k!1I{CQVMER3YS+Xd)^z9X0L=UTE85`)^%Id)kb*|ufag-H}P?kbfpg4ICArUJ=w#7U2Hd{CfJlyuTD{y2BP>au|'
        '`T7~U$@S)n65DL63>xHd3#Y&*y!ibwx?5$SszqmNK0Sg~tvAaYHhWv?`fbxjbdjz<MXN$LK9*{;{=CYyC2yYP_HMm{cFaHCntQV;'
        'FM*2!d!kn*ub=-6JzH}fR#jg*jtq1#Z!2E(tc3%-5|K#|1q5x7P9y^lrzimwCo&2omrz1fq8N!yB4Zh+fQz+BW5pE)_{k#T6XV16'
        'dq*F5bFZ8Ax^y5}sR`>8I;YCsOUF_;5m4dHm%7WZ9f&O<jZ1M(#!YESOo~Qq7quF*vP4^J*_Tz;>C{Wya;Ik8DQwm4emUGi!nP2x'
        'EmUf)w}q0UTZnpFh@9L)Y@mhcDJ^vU!>bn`nkJHqvIodwgQ44B|FOK!`v{_oi+==nyaao^-#vcHe;~YWmURYLHv+D>E6=FP<Hs~F'
        'imsZNwJnR?vJ?#GZgp?qNasroU*ctaw@!Y`U5!uvmp4EBlmj<=1FEvbDE+kB0nC6-1~rC}f42%-d~UT>j{d-gAMc9}x;)@+1@*X+'
        '7Nt3o%kj0X29Sl>d@jD1*Xo~Fl{;rvCC<4Yqq|-ClWl>*dFD>3@Z?u0qzQDt32>wNO%ve3Ca7Bcn`wdTAAY@l{oHlrsM2E~5JokM'
        'OqdYJ4>Mj}zj*nNH~-_*fvx%!tY)?OJ(uLcfM43~)(;Pbm|Ze<6<9a1&*kL0OG>l+$#r{}E();jxO2ei)i=yAi%@ky(YpC>dFxP2'
        '3&LUUqKB<%mHDpx!;ANCuRlEhPv^R<XL0c4a{SZpm=2m^Eq+(vT28=v_q%pKRP<1JiLeJ1JyTw?=T5p7gn4B`>1z9s^P;0W5<t;M'
        'Sy6LG$6J%zDhI5}+qD9J`sI~tRHD}mZ8z3N9VJ6)JZH&YO1}w*ERvjyQP9-<oy3bxb{E|ipAlJr#&1jCpWj_B>;}P4@P^AbQod2='
        '65!QYS<1^dQNGFYO_guDs>W7V)rYGJF|FRqsxknHC4fU%@RVSjM1)3|V8T<$BgUvQk}H`+LQ;cdq6|}p7@7zv6KbS35%f7+dHbz*'
        'ubk$Uws~8v8Wk}fYY7>rNmW!>g2cq9<crD`m!}cRg~_2ql*Ty(X_eOSyGvA`-@N_s;>~M&046}zHk<XPY#;aGrfK~!n}^6m|B07R'
        '%?s4twfZmB)3lCq1ql_daUiS(?FJ<ZQE0(UD{umE&{TzWBu3>$iB-j1q40_N>EORyPlZ*~sCx10Rp~9m?SBJm+|=5rb0VWe@mSJ4'
        'Tq||NnMe{Q4Ko71QY8$JOiUx1#W<Es2`W;FbS6Y*uvCekdVv#u={!d5)o5T>yT^^OY6zDC_G$}@zMB;jO~4-(bH$cG+Txs?+wT<_'
        '#f#N;Q!~^0*NT%CKUSapz1x5Na`WDSz64ombCM6I!3Ec=lI1&1cxUc!cOS2`SbPRvnmYWX_)^9jIAc5y$#Vj?Vkpj8hS)c=hzxwk'
        '$Ie8;{wZm;SnfaD4`SXfZ+^Xb?KT<i^6Pwn1zHc<#x@!&V|ETBcBl*UA%o;&-g%{0bigUSee?Rg<CX~NJ-5~qSwH0LuH;{Na2Mqd'
        '?$J1g*&_U?xjxXsPvCWT#b*bkg3sM;)^}I=`|AGD8?3p0{`}1^t+t}QKFv!7qb+=>B2A0+;|^pnS6^1<F7<&TuPx;evMQmph^+Rp'
        'lh59Y^PqrIrf3HU5=5B@23>bK{y|+rRl!^b@`ivhVuLHWc;{zy^^G1&Yw8Nl#%>6&*bU_>M#{1q%8`(v?1qT*u^S@K%5I2iSwf}a'
        '4Z)!T5t1}I->7rRbD&?Aq|0-Z(!n%`=unzNM$nv|*jCJa7N_h%76G!VAjGl&<;+ZT28?Sw+Zi;nsYwsT$CIAX5VRmYs3tx5SWrnz'
        'P)Vl*m5s9;=1AuNl`W1$i3d@V7Du9jp~&G#l;<<tJr>gDNDLsGNV*)UDm|SeVUT=UjzsCn94QxSevU*+b$0aWl4|WBb)IAOO1m*8'
        '1pEg4CV<B)bzvq&nOE=I=#L78xN?ylFnrDXObT_G6q=SvQGPm;BB4yG%bfU;MCnWmF#?$s6<sEk<>lw&Q9c=DSB3;?-OMY4>NCnh'
        'I{<0SD~Rq2^84e;Y|r^f`qY-8ebkm%YRmi77R^Cv89q#DNjRmg0I;`Hb17{Kv`2YxvajQ_lolS9#vRPhB-X+BdP+vi$h?decp*QD'
        '(b@{m#%LL}jMnG~bf99i43|b0#5x%}AERabtc(_*Rm%`c4R;uAhEw5C!$zA+M$0f|sLN;x3um-UhB8_@hS7G#wqowHIBgHIc%4@T'
        'L6)UvXS9CfI)c#-8QIi~mg%Dz?Rdh_VYK9HqyXrWjFux0vZrlEn?b#-VYDDR_gYAY(HfpbeMVcBPQYkoGBKm&_;f}KLe0-;=~u1J'
        'm*T9Pcs08N?=oRni?cEeJbZr6%IWExm4<Rwdg0MOJ_%>#Z2HkZGL|B7zK<f&J)?hQ&e1<E4pSvMf-05B%4<swRboQN#du&BfcfmL'
        'rb?nj94)F;z|BD5HYHW!a$c&WwLFa~*$U1^m4FOa4_9VUR!?mNGRsjYRpR=5R7s$-QYF!*7?p-MR0({QHm=Io+FVg3$qF@XQ6;Qc'
        'FjW#Hlq#_iRH-Mn6?3n}*@J2zSQUg=mY}m!CBJbUL6wG#Y-*|`*zr_pG!pGlCHggDOY$`g0t)T{maIjYm{MRt4rKy;AwElKQzj0g'
        '6V|0nRp|tjDWMZnCLvCzOd!<!l!=vUO}=imz7%y5(yQTZxW`lkLbRZq<YicJUg{*&>C}mZQYY3+q&AK^k+IZi-0<ST6^TMOOK~dy'
        'TjeJSU6Dw_h>_eocEl_(qQlc7N$aZ95TpOT{@IlgTdZh<Q-s8I^q=p+Wj%r=$zg)U!U<M|$GjHj5-bxT<%4ZLtF#1*15y`Vf`tyx'
        '^{V0ClmtuCSqT>00F$Q>th$1;5iGzB)x*uS5sfwy%!AjCNq#<pCB<0@mXvKnC^ftxSRA0OtMZLDmjsJfYwTR@)&d3dE2(-*76<qh'
        'KfIQ)zKx#LR?0mFN0B|qqDHZ2{b0|qw3lCvT#5NtTSKN$uNi!d%C5_PT0=H&4VkJPYRgVsYQ&-c%p7XO3D?M{<Q;01ah>$3QCT{{'
        '8Zt9AHBzLfX&vPX66&wBhAggLqIy|MMB4wxj3Pyx5SD0x6QwgOO{OEwvy8GhQ<%h5C@PR5EMh#yL~xu%l*$-qEW>fEL#U9VUX5-8'
        'GmaFG5*KuF0@Q1MDx{c|wgTPcD_TQFzRFP~#k+)P<R}u~H_<MTEGf}@ZX?%_5&tL>amW%mc@#;>UZ3VcMZqMe0!3b1a!3y63VebG'
        'JNfLbCOHC;E)1jvfDXi5Q<5B|dL-uv92QP;s{1^e<5cILjp8U>Q5-HJz#lcm5mJy)ilfo_D2~Qwr8t_j&7jn8hvG<_x+}37U9KpO'
        '%=5^1#*oUi>|q>7)6g*_F=7m<C$<%Huf5rWYWP<b1ZA3GbB`en#1F<(oxwQ5)Qm^-<HwLjhvqwDNbGA2wmTOr5GJ|A7?KvA2)k$#'
        'B?(Z~Sx5%vMTO5&+C)hRp7j@!Ri&XsiIM?ILJ;cnq&z<tJ)S9P890cvSE^t|Ev21(6p2wC1J=BhcF#4G^y1xrIZsx3wY&}Zge1_k'
        'E|?QC-z8u`u^qmIU48`6todx#tAU)GJxr_h;lRDHm==)0K0I4GK=182cvi%bBFf_@eNABTtVEpRUUDo}?B^2ZVD|u87v}_Jxhqm_'
        '&KS05lH-#gZC$|`Q@+_zB#|*r>Z}NoD6NBYz9G^_wRozeZ-|~Z>l<P%bEx#Z!L=fbQRXOqqthj>l@yorYTUdZf`!kG!ia|k@8yW#'
        'eNS#H=RUh5_8{x7RaFpXUt;d)y`MB50c;1z<K)@kkUTz=Z|H?GBaqVNlPN=`U6=2j6m^DBX*+uyQl3DmY#~~arPy6aA}Qg@XCiIK'
        '55iKax`?(aogy{D<muy(J~{TEOLg(w2;{<w-A{rrHaEfyBLo;DujaR5AaMPZv}Q|5%J2ndOJR&pA0s$AJA(YWHdYIZ&f_Lst}i@a'
        'uY;Gt>)@vi%VSIr$K_>sT)x6PUIlh|jATjTuI{K|kx$8M9wRvECcgq>mcejp%D6nnY}UZM(CDPeNA~>lkr-@KyGenVsU!0eTy=0{'
        '9%FF~iNS%DAC=q<2a_1w&hAzzc|&5PkWuPHxf_M9NQ@MuzrX{92j?*kPVc5hMCW^QTRHbyojs^VXjMUwb&=WgyA8w%#<Q5gc){c}'
        'h8&;Z?U=A<hsf}!KxRm|9uwbUV%1_dQfSRxb|Ynb&4;y}HoF12Q{0Q!SEXNNydD$!Jp}BvjI%iXz5@1`Ft47sp`g-<;4PS^5fOSw'
        'wWp5QW5N%I>{VFEzVeFR`*WbKN`VY2kMs1kfrYx7DA7%0j5(n?*z4}Wy2OD$B+MI&Swr@MNTyE$yS9S!p<QCP8&W2YSRJz0lw%%@'
        'c8ThvT{0EgCHlN*m!kGgEv23}Xjf&FxQgHCbcuGM(;@VP+4h*?(1^Vr5wY)yZN=PYcFZ1R9X3W)NsxU}GIz+{PbbHN-62{zIo750'
        '=#c&RcxX`Srwd0o(M3b{lz9S|x&>-gzTt~A2}OhVQeGQryMApXOM5Z<s`O-3i@Ba2)lwc9wBIY%B~a}con|J(Jeysy=L*iZ(JU2S'
        '1#hFhh$y97k$H>+(|ky$Cx^2%U{<vbgR_<2^WLBXXCr}C%slSV+XxoVVx)?F3_5_e4C;q@)=B4}(0ON76Ra^iDL0R;;Cz6V+KJVX'
        '6pEo{15GVd_#_mD&WLE4XKpo~5Ye*s<myV*8$=sPLyWs4O{3NKHdtFO>u*PJB^|L1VetIwYV0s9gxeFnmUN%-342iOvPo4EWMypj'
        'Io1Qr@d#Wy#2_aJwv1mgh%26gTR}lw=9_d47U%-rNFhR$v&A8Zs{H2DMhCGZ`K-SV;;l;07sr(+AYL~A#A`W!9M_~c&DeJq$7RZ|'
        '>TP5g$AG8XsE-gK@Q`v(4t-g`<ZFz=uy5rZy?5wf-#8;iGoKUnHbV`5p#fwc{1PF9{qG*|OC2yo!*&RscLKIl2%oeoU0uQXz%REG'
        'uoIGrtO377N)`@&xn~A8oeKPNdS39$+cU5$U2ni|LIrb)pQF_k_$3PUI3AH>BDy?y4mQRkLb`p?t)%;mPuhcO?@g<cFe{sV8ukFo'
        'JR(Wu5Zjy_{PN=`VjmMR^XI92ih&J)UhbQhjobTrCjdE^yRSD<7z?l2v~fX7B9Zm7vQ(vCXPB4k?;*^qK#!8|CCn?3U&Y%{Fr^g9'
        ')<)l;)KrlnrJfw@3Vb-ui*Xp(t-PW44jr(YN}}9Je~r`hHbV_|8PcjZiIHf|g8l8JQx^o8H-82&E_GUxz^a1tfn8yDtV)4MHWPJ$'
        'k4hPwhaC%cMzAY9n^utt!LDfUT2<+K19nrDO70@YMyo5Z%Lr29q`A5xc;hNOW-sQx=vLBw#;5H;wb$lVNtl(*zIoLEs~it@2ifK1'
        'U{~n*BE7N)cI8v}D=5+{eY;xW_D0RAMkGcK=w(2eq}P1f_`oQvbr1AbrKd-FG4X=llNKaOd~&20lTpfhiA3#~;9PaSvrw-jeqC>4'
        'Lz6HfS}6)KX9|-c?VcR{N*WOAC1L2da*y6SbkJ{xm`RY&i+Y=(M!#G#!F!=zDs`{}-h+ObgN9g;UzTjvP_L#`pR@;2UBUU#ue8h5'
        'GOSdSBO7x?29t;N0jl(@Q)5%1Un$Rver0=|TBYj^`ppPI!d3o8t1I-&mEf|6e)S0SD|K+FmyQVa_C>dn?lC@w>_N5r7F9`*l_@lP'
        '#tlEsJSLai0NtD%{VIIPP%nFmgY8AVP0H!E<+-RgBaBNo)XSCR#A`NfT!4XLkqC8RuPr`bu=kW14vNkm?3MEed($K~27f2PUd8-M'
        '-UfphajH=p?@Ej%8Pw~^0k7f#;a(aBcq@<Szefl0Vx%(4mCtp0TcU=%k_y~|yi9Wy>~$xd-Jry*0biySIcau7UBUSvud-{^Fp31&'
        'SdDol<D3O!UZu{6d6j3i8l4dH>h@|itL+Wwg|<l(;p%^**cIx{Id%{A5<UX;Y8)K%9kT_eM|LafJ_987pxS?{swBwLG?_c-JHRi;'
        '!`?xjIXUe0<jW2Y`W_KC>%d<16bTE9`fA_eb==;W6Ra$Yj2rfqOf&8^pbk*L5jIh8hOaF?Ti_Rw69BL$`}dgxzxl>Tvj=`zqH>q`'
        'eFc8KImB@{EDHK5g=!;V#gQh13O+d!_9XcBxym3UY`vuaCS53u4Q8z|)Y_eTo1%uoN-{zE073I$PrL^Ta|apmFbAz>js60u(E6lQ'
        '%S{dE1H;;`bHg|zIBf#JN?{(HsEi=bLN`7U7$yjx6%6McZObq!eRsexbcva}agL+f6&Tit^md~sQig+Jf@p9Ec+7r@ec5YK_n9EG'
        '2U%YZcS3@<q$h~Y9RnU<o<}4s8)BeSgJI&yv3<4}upCNQ_7ooTV_<@OOWtvN3&wnP3p^eN18YPv_1aAbB2ZwzqBr-!7Eh3jS&500'
        'F%wUo@X^VbmAF7MW;#~K$zN8-yE&JMH`_Sw?#l>@u1wkne4y&(ET4JPE|VrF`0;6%X=vJI`d3K1Oq#^nzO>8q(rK3o4w=wBVn0L+'
        'di+Z4avLHsi4q?=@~V2xZ8R;nXJ}<##)Jgpswt!Vd1PVEC_g8foiwexuHbCMhG09bJD;hai8>`6)@(RuL!WzKc1B`@`FV*A79Fc7'
        'mE9#aN-^3Z2en>XV#6rvl6cKTIIqFs6T8Rkk?0ZKO1jtn>_H7at4hKQZT6YnLt%vR#AZ00FgdfqdbTisy*+%xZ1hvyGbqdt-pUvE'
        '6dj7AB1YYLE?{Shc}=KGabzN-hvJmQUuBq|5d2+)`Qb7~e`hI~i8u8)?(U+9X&jmM@<xJ$62l5Ub(o)!kQv^ATPa#U>Ay)A3ezl2'
        'T9ZX<hw5z#3x$D?355IkJhTq>#e1-@aG;S0a?xboN!}RjU7eJkxvAlNXqeb(-e8+xdG(wZV1|?juW}^BGtXO0g@%bdFB&H8dEQpv'
        '9W>0aB-9~;j%t@^nB=(}d%0^6)!}fMgwOOIv$JAf_FB|^CMfJdwJ#@CNsz74*{6CBP|xvbc#wil4u<IoQ@uxrOZ^G$zJUPfyup3y'
        'o#5TxWD!hCV|Ru(m{c*K=dqR!FyJU=vbPn9EuJ8_A7xVq_bEL+xDQgzAKYh8!TrJDzBey9?(V1vik=ACO56;pt~kFyaKFhNetdAB'
        'g$DOoCz{SjM&E0$HD7T5)%Dxu&965tx<Ex^v!y%E@*kjSY?~Ey-CA3@`CoxH3dhVn(4z_T2MZy)LL^Y_W@aH&SBTYpp&$S=W|l;E'
        'CHehvWwz&hDxPs4ws+iz*>N9!sc|0`GVU{CzfFsR{r#IucA1nsMn1Ug?FDPHiy2p4vP(6?!9aV`aUVAGxQ|e$QQf+N^D$jkkNYqs'
        'qX;!j7u-N_@=C(k8JR9S^SBS|jQdo|?lN7CwQjM+TCXkB<)Syh3HX<XGhG%w@H1xnO^@tW)V&614{ES`RT5@t^AG$C1eT5%_!$f^'
        'P0n@MMF)QHQz$%e<cE7lepHA5YMQzk+)1AKKzePc%YX9?3qAa|EI!}J&nX0$&p+~WiOfDRPnqQ3*~kwkes%BQM4pI5wib90q9{Rw'
        '3O@PB4-Xmn3EYv>I!gadx?or!4#hr?>TQY|3{#{e>5u&2aA&*+4NC_c$sixiXCC>Xf}@l2`!qG24-fNt<VVm<I3qul5)r<@gL_7P'
        '<WzW=pLyhmcSe3HeRuG%0F}h91vIK%;bBTS>n-pQV-|Su@R6S}J9K(vx1#PdL1hoBeL1U2f^1F9Kl0-zpGS=R43W^u(XcpS<Y#m&'
        'eQ$!xr;(rfnRrKj+Iw|^NhuLKJJ5qkiT3UXwY7ABfuxb-edJpePcZUh<kTZSVuFz$BQG%W!=FZe21kAb^Q(CW3<?$*(jNJNOHq7*'
        'ksmR^$PW)4`RR`I=x=gahY<V1``m{2^>pEV^XF<8#$-gmUaYv@j5V*frZVv7;m+)g7v}gCxW#6)(ggYNkXOwcHX}6d?p6u?z79rG'
        'Eiz+oB0V;?FHYW+wGkm`vq(hvNsBt_3Z^16A8y{gdhz<Y)vbB<9C0+Ld*5~97k{7WdO?Z019qv&z}rDBxv3OQU8Dl;jL0=+M8XJ}'
        '#5EyHNE{~(AydOMuR5}lv&h;fW=*Q$LDq+lW_^;Km-R{B=|IYU!DW3(YFMkMsJj5m`ZUtr99IM@7S8&b)VPO6LCBaLY(27DQTO&$'
        '_MisGRwY4wl9aQLf(!&%ju-_Q47N<p`=pw06r|7m@||y<!one=AX0n6!UT1=V3Nfda=D-`x3KQpP?rlP1gU<W*Q)q*E=Wi^H5XJU'
        'a1dm_R2SodPs+ZJ6e{f3_b#SRu`ulgFjND_y#Ogx^}tQVaPW+z@Ecg`-^PWCo&^_rn5SaB=i+0Y;Ryw(!#wHf6U!7oJdQ@th>2wt'
        '-11wB%RVK+26=Ir*Pd$j$q1)iq)FM~6&y99n{+76lQ#IgLutB79eMmvnyq0f_SrElITJlpYEj3GnT+bZ1%%OZNnL=fdM0|P(HZHX'
        'K6BPL-O2h^8LmSQCCw7$WEgO4w4#TMN>7GEGGdaPCn4?-J;Y<^VPAGD>b}lI+k<Lo%d3*0UPH6_>7l>lIEEe$bs&?|Lr*H%V0t(j'
        'TzAPK`Fip4-hsihlR<A1Skm6!8B2yGb_WI-Rh@xBYcU-%s3<i_KN&(*JOLTxcxp1}$u>Kh41!eilR@zfDEGxkpjLi8??7A0NTl0y'
        ';Xv0Fx&R5(`g9T~LP?-FaZMQRtPQ)&nlOqSqdj6x81vwdhN}e&fxAMCS`#*r5Tq-__%&e@NkY4lj9e2oUW^topon#e!NwFdP8=Sf'
        'i0=yzi1F*rrVS5JBm%+%ctm)hg4_N+v=ttRXzXq))ZlV&PuqkCWVI5_VHyl+8jR?t3=dEw=M4`qhUiIS(@hO$n`ui?!`#!9>t<k='
        'qjE}g5bvc(pN~}2CK2daNHxV>8d|EmOR5c%Zo*ARvnx`akJ72$Oj}NaNj1eJm{gNdq`E76E$SW<<j5XWQv^|!1lby<vy<upb31}m'
        '51QT7q?$H~I>(dh(Illys_D1GJ7y)-6muWhARSU|c&6MDRxqn_+EveDx}-W)+Vp4JR>c#LYB}`?E5+h;QY|kr!YZFg^&qLHO_JNT'
        'o_7JE5gBPiJr0ah&rhl;R;QC{8A__VBdOv*A{G3VjjU3vyVPwYbHahlsY%J|V@}dCCvl;S9n_N_)d#9ZFsBkz`3=QoPKri~dcl|1'
        'oNDI80fKbLXmU*rhHaBFCqiasPLkVb^s&sz)^I-NMCzO!ibWA}m=hB^c#R?@?2OEboHu6&C7qldmAX63NpYeRH+0Zwwq;HnVcpHu'
        'u4FiIBEcy;suZ<>#Hla3m2|HK+JhPxSe1mC+WaXy2CVHE;xuG+lM^R$Ldp(#>S!dJ23v+L<@%P06ZIwN0HbRWC&gKmxd|#c$B20?'
        'rbC=G2#oqWuvWzr5GOr3aiaKi;-oJ@oYXg<+!rHGl=$_$g9jBCv1qST1YK7b*nWyqdOC4Zp~Ol36}F$Ebnk3Yb?NP=C=Hn{N=J~I'
        '3h(%pxJ7Do%3|gNMqX8KNR2|W8zZNPheN7KNe!KOwkVK1f=?nfbq(huHB{E5CNel}CUSBmg$yP&RGpF3P<>ufQ!h|!tGi2TVy<+H'
        '8Pu9>NsUIbn{iX?5u-s22a_5$iq!N(x03F)KzmRF(W;UlQ>!z6&PQqntnCO=GiY^_lNv^kCpG$1Qp3L;+&3?&X_Bh8jjl~<V#(X1'
        'K^m76b9)xkB{h+bQV*#qizgs8X*4ydVf=Jb15(XTYV;GS874JM`1QPt2V<?G4yn<EULfs0ZF2P<Pik~1snLIh<SUe^eWXTTGWiPi'
        'q~Y~}o$%x<71r@9uuEv*Sw<@Hfg-P(*MtUu0qYYQDTCqEzT_+884X9LGMaJ8S1_kSpEkp-uHk&?SEw&XZb14KEJCNqa&l<eGI1x!'
        ';?4wFG{xQx&~+V}wmgRrENI&D9Fp+E)0XEDLmX0#%oT!kguwfRz`;VuL#i={5GqJD=8!}mR*i|p__5O^iMEgXY_^U|MUG2Fj!O-_'
        'KY<VJtkY6_+POP2iQ)@#XlI={grGq?>&zhuJG`^b9AfZ8s?kz>))9hEVt+y$QjIx;kU^?3ha~E-YD_FfuRGGMe22$(M?FX?EhNoW'
        '_tD*Vib?yeg8QxVoux_iM&4y7yFtavoXES5RI1%XB@G3uBJV<@UP_WGceXbS^775|pO-hUe{jX9XLePWvx6XY-8*w{*&U|3+!f$A'
        'v$;2S1;67+wUW_#A{=gz#Vgp`>-X<nnespkXw1XLm`@M+X$v6m>jZQmT|Pv&g~@)39)L35+U761g>A*f&7ZsF_K(#r`B-opOZ$uI'
        'EIG$qM!-0W53!r~vnX!9<-h&@2>oQXN=o6)r$=D1>&<d~fA{5o@1Onq{{b$aN5='
    ),
    'budget': (
        'c-rk<X^-1Dw*4zcKKB6JmjV2tI;rj#bhfFad!~U07+R<*qg{5j?aJ~7{omh}L`jrH+q5mKGLtw+*``J6>hfOloXhRs&*J$qoiA^n'
        '{r%t1QnN|c^M~zfoqsdge3s1@X12<*joCi?J7!d1@k8;$`eT$QNQuc0&o*}v;o{lfpQS9NQpRygC{rv=rPi_LkS~i;go%oDnyG}w'
        '+8E8KOazWHZEzAZxQ0gh8I(2uKQoKJY|SPwpZ)d2vp>vwX%@3P6QyPiZ=c~tEaj0@2qBEh7ejkr2YwEI75B_v24``E3_>wOI!OtR'
        '6~ZjZKXE3M(2^1)kt8A$68>V55+ri{8Tgk;2H%L_a1D`M82G01zl^brLr#%GJ_f%VQi#qG<N3Q_N+7;lz6|~o0)Jvea_Qh(f=D4b'
        'Dc>u7WW3ZJZfmLjT7M{WiO!8gU&Gj^>L|Zd_3qUD7V`V<)FEE9D4Qi0yv2YoVkB6HRMKkOXcCn*Rf%8K`+n1}Di_KlU~d>oEecSI'
        '^13>Ui>Rpd<l2$n&lr^FmX^OXMQKrTRh}x}g*aSZl9$JY;+YVoFEQr{u=^-Tn|)8*$Oq+ck${&`)T(#dDKA0+<q`D#_5JnzHQMW0'
        '4GZS?(XEN2jRRAJ`r+BbdUd;w?l(D*iTr4W(j2=qU`9~Iet0%tZno>kWIJCiD;V<cXKQnte~)IVS(w{sYi8SZ^pN8aXehHB6J&}<'
        'wgomSwT%+X0ZpCPe4cN8`Lu0vjEdu`8+Y?%(R=|}pl^>4sHDj<Uq*{rlq9Ri<rcu5@3twbZkt(9(-!wWdhkkHbOD95wgqozTLVlh'
        'v&0xN6>DagWSkRDIfZw|6xB)8&9Yi9zQBhaH_dRRTCDvyU6|Yid|B(q#H#!ht9I7S<Go1_D68rPjS}8c9+x{L$4QluF<-_{>-jc{'
        '!7O){K;uf`&{dJTgzfwu&@fc>YJCgh&)0uKK7gM91r)P7;uNPb)InAP!@@?Ye4B^)a%Pr!T|q@k3nNs*t54W=iAmbcwb@4NZ7!wG'
        'vV^i!ag$1(sa)!~GA1ySX8_(yZ`<ocjAOr-NQ!!HfPp9+HgqAh*OCdrJyRu2AF@TjDm#r$P#I!PoXZ{N0{(x<9w-w23TK-5Y81@X'
        'Uu7JVzZ|+|QlKiCih!E&2yB3Gi4jkgffgy_CPpy^CYKVKX`V%x!Y{D_3S{7qk_qk5HDE#lijV!xEkIS}G`GNYa;@%bZsXleCfV0y'
        '#>Y3A@y_N>RQ?NI)N9n^<D0uO%Pd(fv-vtV6`#x3jfSu+jq!E~A#GMx_bZhvyG>7=+r*A`hv(VjTF0qXVmtfJ1}ll`j)mIBB(9r~'
        'cvr(Cb@eH=wc|8AvA5yrG&hoDwlVTIJS}r#O7`qUY3(%#LS(PT3Fn8ZlwuiDXH=uTmBLzgYW+g7Ppwo^zuv$eUGI;epTN+&D2+*$'
        'fZ7c-Qed{6WroB=b0MNg8qjn?08_<AYm#A#GOmPVQu)09ulxqvboH25(}(N#?{9v8Gy4VM+4Y+bH^2Yy(k4yb-n{(z<(sQllV7fH'
        '-dw+`e<-f~>E`P7^^d>)^wagt1VrCHZl<|{zf3;O)9u|96NM&sW`29OokH!yCF^-=%H$jfPSNMeC??QY-bdSMe7pWU*+9EpG&Iw^'
        'nm$Eq^Earn&1zxVw}18Wx9i!>)tjHM-%kp3S?UjpO|vAoSDOmThBSkc+&ywZlRxS!4a!85YOln&NXsj*xz5ySRe3gNvW~XN9i)_e'
        'bh6H^=HATi;K8S8a=U6usUJ5_EQ?WynmoDvXz#8->p#zKuCHGFK1tTJxF5~2!KCPQHd8Ty&g~<7$lK@1!`+w7Jb@lIo^Ll(NVt8B'
        ')_L(V%U{MSd2K*P$?CyO7pqUXQa_qyuIOmdzWvSh`|A(0cW+<5`2bZLr71YY21?7KlyX8Q_hx&yN~e#|N&L+|Zo7cj*RS8+{62eq'
        '^=|gt)vK2;CQZb0GsRd{wg8eALOnn|ZKj+;J2Z*5TXX-go#J+p*Z+F?VfN$Ow;yKjuWx>P`TY9*?Cme@OP;^`b@uk3Z?0c-RJPtc'
        'l-0^J0^jBjg^3tSvuJXgZl|kHOOsCK^`|X7Z1Kr0p3L6ey#49rtLwh9lZVGy(O69J1fC>sG8X2eS-_8z<>%Sv@!?^$-kKDChOcIs'
        '*I@qTA(^N3S1^jjDuz;_%~)<0QC=^g^T{IO(zz&EGmu^gH8B}998iz>!?f*(&OW?+eSI_g@fxfM-09CpvrJ5$IrqBwF}*e0$w#x^'
        '<UR&sSPC{JlXZUWW?MEDQ!RX@R%)or#VrM7o7+w4-SB+*-_4f|C~HxE0(&!S_?T^G_M+SRlO>8x!Xn+~*QO?ZymeHt+I-%C>F1?9'
        'Oml>qe3@lMl26>{uiifYr4g1)Hmk=qe7JisTfwS^C^Kbm1}b`p;`w5}{Q{|4X`m7CPejnkP9Ds9zDj2qm~iFD=3$lG&DK#~3mHu&'
        'MRUHH(n<6%PiC=!cC9QPTu|r6ohL_Gp@cFOiUOm_TL+0)5w0!Xp{3ctRnWU_{+L21HUX3PXqvAdp^03rr<7D`n`fYq#|>nGPk8d@'
        'W3-rOV5UVwYVIGwqE_o!4w=1Lx_Z~>h)&YgeKap@<1W_^SjfkDZY{ZbW}C%o3wq2y-kPOZm$$%0LY2{Lj#tlrfmW@#53|LWokj*W'
        'nCprct!mNvO+{o9L;*b;q!Y=YcT<!Af)g19f=ehNDp8EYCXum>Q^3U9q_N@(1N3AO@rm)_>b+wRym{93YE^a~S!oHY6dES$>t&}>'
        'bRb~D>o0Y4Uw0l=3Te6%Co^tROHxuOv7OXXruD?C)UqA3-szM}+;pd8+(~Se?S46|AyH|FR2nL+)~li9WDQZThRE3(VmmZM&(YA;'
        'i`OqdG%Au4+X7@-LX*GxG+X9v1S??m<PN&x8TjLJ`*@%KKzOZ|RR%aW0-m@nbJ+B<iJnDM)k%q`O#~a-#VB3Omj<qLzQph)p2dq*'
        '@<-mu_@sYz{o>~wvQ^?M>xWT#Ki>ktfF=etZjpbl%(eL3(o~N7z=I!`Me|%<u$V(RjqF8Qj^J`!T@?a|!mK|Q-^)97bJ<iUpG|Rc'
        '-bIUT`BU}uMVFa(M@9cVMIn!``;U(sn{OT;?|gi#ZTIP&dOGU)-TJ+l2CiQGcJ=1D+l3=*!9W}0MAartSYgAyGG1T3eD&koe>r8~'
        '%5(}YGhhFiOY&f#N7`&x4-bWyT?#f0ESpsIa(3Azk(vGMc6gXh3W)A><bcj+l}e0^nZ2OUZvI=Y9a;{rPRt^D*qBzD@6In?zJGW1'
        ';rahK_hmhAgPO~cPrpez=!UiUU4d&k0p%@=l-kLPrU?>sbxF}8<!#iS=ji$m=GKAI`Q{<#LMJyNfSgZgLAp)G(G7{CjsxE0ZBBtL'
        '{rcK<Cec$syW?u(jFOKuePzj3%AOJ~nIt*$qF|x<JBcUjY!TfSpAngWrEkjKK7Y7e*foNm;0>2=Brj`H(4l(7c~Wo)_>q@yqI{F('
        'n=0S5Ev72YmWPRbr}n)pDg#(pLN<g2PYK3JL}-KwCOnlqf_6k1$(2kZA*n$!QHCi)3{8ZT30SN)kr0S0Z+ms~+EK5p)Z5Z(R77;F'
        '2e23!WRnUH-~{{3dty7^G8^DYov}&Yio`kSXr<PGyGu)-U%&hC^6i`I0!)CKt=Fq{sUNp;)3mP4rV^Rx*LYEDUf=t0(`vU=&(b=^'
        '6(m%+#euLDOgAV|h=K;!tuP4yKw}f@xQoh@>_e6IiO;l82l3^0Dk?*b?2Fr%wOfYU|8|&hQ)*+*iHs7(V@dPitke-_B1xDu%n0~O'
        'l`uRqF^y;z<5)5!s7NK!nGl)5QYC(}1)c9Jry8}_qJd9sAJ?X`X%Ir7Ix)9uhIN6OA51YbYz8zfE_k>7UeV9Ve6w!8RKHplTKs4~'
        '`&+kv{CfS~0lNfM(&n@tvH?q6%}ZYIsBmGHx7)j^7L$*_L{o>66ko~+180oq0eDWBWQO9LSBQP{h{%rb_|$nv*gpZSN|yU``@ze*'
        '+4XPNZ(Nn(E~CzeQ$Ty5n@VY{jL<n8*dZ&-hX|6pyzxq>bVsN3?(LiRPParzuijcUvU<q*T*<idP%g?V?$J1o*`oNUxjzuWd+2hv'
        '#b*bcLYKQ;uNKq%eZGA3hG(vxKY#mcOINhlrg_O<w1E#cwlrBiZb1e!{W3R;)CY#VzLZ19DkURaA`fQr`CE}M??n)mv;zPo6*3TO'
        'Eppg{x(v!<TL<TcU@%g}QgYcYP2s9%JdMazxi3a$2)AU0V6J%0#|c)Lg_0Q}E=OjFyeOF=s_g)!WjB0=-~{@u#?%`tE@=$`sMNJ;'
        'TwD>zYKRVHHRK3Z(-XTAv-UJe1f?xcW0JO54YhefJPM%AsI12CRP{5R=Ua|yhF~}ppU!ZO#+wDhK{dm{ry@vNB1k$Uf^2%m-Gt~8'
        '2(m?pDDl8Y(jr6zoIG_15g~+ApJ%iQ5dgASsxBe2spk_S43ZB^h$uaq5amLRPl!lq&W=4jrCB?$oaeyYS~tdoP@4ZHfV3<1#I%Vr'
        'uidwy9wCeZO?F@$q+mWiZKC{q+C)NWQ<o<36Is!P)>s76CMvqLDa+F@N1A*x$gT_tl)4^Q2GysJg>?YJ7*`P8739yyx!GK@O8PvO'
        'p?y4-R6LgVc`O=(zcPH7zmjnNYGJRpQFHh!Q7Vx>bnI*RYW^yCv3kfw`ixN$h^mL=uZ)byUon<ipH5)w>=$FOj8+U*!z-y7tRy6u'
        '!7_F^2Fv(G87zRRmJ5`&?J(E~vB(+VYV6oDSjn{N*tHfkn7}d_N?_?R1hy-6C1veuLX}f_8&~6^w6q$g+dM%orN$+&JG`oXs570*'
        'QO*z)mg$oz?C}htLt)9+i22b|Qdo{WP@c9aY(!AP911JBL_Xi>P*}}`>5b{x)Bz~0Oa`W~9G_2NL8$R5Ed8p@`Kd@MCtl0$;JJt<'
        'IB8)uDT<M(kx442=aW<#N>b?)kL~e6NGfN;kL{6TIT7dkI1$}5wnxSs+vDOeH=;*yqY_bheaYcQ6vrm<0WY7wRosX|13@|%lB43H'
        '5WqGhH{x<kZX}eTXK<q``^C5sSC$)5k`h&OBT9)-q1=e;%W)%tF3OEWn^aiaZnzPpOmZg>(AaUwjVR^i5Rp5&SGI*=<VcWEa>R}x'
        'M?JACF&kf_n97!~30XF*6#!&5Pl!(mIx;!(yH)*AXL^^ToFT}OV5gI#qp@d)9MP{4O_Hx+oKJ8Mlw>WEM5$oR8RyHtW1o+-NfIMU'
        '>)tq@O&x$FC3IktB*gh734|J-B(c)0$=7YxPeqo5^jdfu;8D0&)B<mmN}|UnOG2GbmRKlRV!dt9jw4ItSh9572;#vtg+ez=YHZJI'
        'cNYm=Q%J(7klZ^w#40L8cTaO9t-B6Gh5mW<iz_3pFrqbSrMPLJtSqZLh*C*%m{PHDN@a1F*W+ADrLx#C4_xzkWlgCh?X8!AG#v=@'
        'hNM)Ij!3BpD)%Niky6#!FGi^(tL#u`1iF&i4mFjbluGi;Q7S1eN~xr5yFh8%4yB3&=FZ&U#*QteQlwm6;tn_Aa7HCnZ_(inM#T@W'
        'Mr<CVD|IDh?P|?B)XLY0sxGSWqD=^LD(&S|N3NyxaH`<7l+6>JzNXUE$`D*ip`IFiT&h}A{e3mqajU^p-Iccdq(zD%rQDGtswg2o'
        'BkzzR9YNpJBSmHE0IR{w(4<I_o~3n+D@dsSp4DKneF^)j$Pj7&J7&Zv;)Jk73!EsOVQDfQX`W@2#hJn+rb1DH6k!qLF(!iJECL)9'
        '<BVlEj&%qLQq*hF9Y_`##8?Y%DPUydlOV+^X)W9)U(sqX@>Px)Dc+?*M~)creY5BSX_6AXdOLD881au75r-y`vqy}S?6qkgR1{8c'
        'N>JqWC5PTH#7r@U)WuFdf2-&XgG*SK-Y7+bG1rg;N2wmcIRS@t3C>O+Rz2sbTU%85FGg{cwiJh9p?OVl7*PdB4Wc0$U5?^td{K&{'
        'Ny`naeK!<`VUq_SYJ+cVxuiIZVy1edMvMh>98E(<jl>b7Mm@1BF>8P0nwDd|mAhd?D!;YpkK0T^Tg9+(hmCfG4(g{mGlJk~X9%jJ'
        '`RT((M@Qp3!$$0DjITR4ETAQMieV!yJVABQVn~c2mZ*jyF(63N=Ob-~#DPeVq|1<OYA8dZWCs@^2=xh4zP~s*og!%&IBv98s$fGc'
        'r5%0XC`$=7_{pq$tkI*FH~(;IR(Y+wjr2HYGHS6V&J{<y4BH_}*d<1Q$(qk*HQ%vOW)IA2eK=MxDliKWU=NVBJ)igS93aahlDTpE'
        'x`XtopaQa7=ZC#?I(x2haL>92$h!C@Xm7e=d(6>7^)x@}>GV*2o&ACvwN+zAJT<hL{v<HdBzUJbMEXb;54BYrqL<yP4Y8IdSQBrs'
        'EH@%UPT;#S=Mu{bteEbYH<2oQc?d>4G+-}}2-tV!uI1cA9x1Las(NZ^6T*B;j2*G}6UF1>_PYq<(9wI0<musiL!W4?15)<(WXSMn'
        'x3~9Bfx19=w7vHmQl8+bY=K#BRBRkDE3hWi=OXPsU!*Z+y>P!x9b&J8!8d<H`s{drF4dE7c0iuku=~3j9J|@U2%`cRBd_Im5THq-'
        'q_vPl5Tw}n!vYxN^T!2F-tIttU5B8BMdWd_$*nIWUoUKz!3*1m4aH+j569wVcr4!H9j^g96h=^%PxJ4?BA=006ed58r@MNCVnKu9'
        ')R3`wjM=Ecc!`)eCm3JlzZ{9d)edcfu~^hQv<WUW3g2#8oI+x7VBsh2(T0Ob3~q1IW{tcdF@nW9bICw$(3Zq--P?Ll3mnd2aPTH='
        '>WF}RUu-L8?R1P50SGs2pjmq_DrqwX`4$;@o3<Shg8H$}3=}x(8HB!&(|2k+CDPd;F#LP$G9*HeiEojxYOxx@QW-fbJA^<T;$OL1'
        'i`7V)CA7zCZ0c7TqQ``O3o-hf0w^4PTS0nEnAgzT7*Hydq%C|W;Z|~&Z4Vu#$Alja)2pyBz3mUZ&*xxVnIIJ>o^I2pg9_sUv+R$_'
        'b0T?Yf4c|c5(oB>uzpyK7^de~YJPf{zRrF*giER;fn<s$s>AdOYZi`hiRvR<G8Dok`mzX@qLwFE6K@c%OqC?gir>bZON6V49fNie'
        'uGHZOm*UVUy*?sJ-xIqMb04jwq%)qbZ9<T1Q8IRv-p?S9kJ9gAl7mO-DLpw#e|!iuXg8-P4r-z&jnY%*iB;+ro|S2m<E$FbDq?pb'
        '@4864&sPb^-CL<_Q_se;m}@Vd)$|NJOL<_Jey>=^;8_rN^f)~uDO1Vlc0E=&z71ok@Y;79<|zZMTx;iHP4}4e;4qd3Or6$YFxGZ@'
        '-sf{*tR^&dr%l&=qfZAFjMZG(qg35f)VQR<o$8>|P3X82rwI~RpA)RD3%DGXrPbVNO(l-&Xsrg85{_jVx*(Qip4roQKrGAJ)2FSS'
        'H&|9v19Z4C{Klr2HZrR;?oFT8M}%ux@cd~zP8b%i?Fn89+Blvf#j=-%KY}aj)&y#dY_1>&V<S(Y-oX{?=Q@)zI{Fy|$uj<w0bB7s'
        'kQElOWxh$(7_}fSQ2hv~e+_Z9&<c4Srws@qO0?=>T$}oJ#%$R)F|V3r$V7mHzO9%oQ+`u#qrpfdC~D0-fewxoD}=n(JviKD0h6mS'
        '3d6g$Tl7AmgLk1m!J<69r&kLV;KdjV)SZ9|9@Lp%y{F^d19+)}fN0p^y<^U=7C^Sn*j=*DemStqtNGPYnnY2(P!Iz#;K7@rVD6b<'
        'O@~6eoL&~~^7aI4Yvm2vjSP+4(F(_)?ZMc2W7b^?OUga^1Mw~oo??yh5z*Ve=#`}Vn5L*Msyl9CQ^GuK^jX$BSmp5n+@0)l@CYtH'
        'eV+9x;W7WFlivegJK!$&O}obJL$@P98p1tv8)!4(Ubkr@f;g2))>}qsQ@_rbF4x~eOjpGyis&~I(-p{X;%yKZXIZM-Fqd$tb{h5I'
        'FjwHiQC*C~V6N>Ay-(=C+=ND%yOUVcX?oRA<J=m-ws0;IIJmzZbcTW;<8Fz;ghFTSiBT1BIj}3LbEXm&30+5aq2?3~-b@_}c0sT!'
        'JV#BD0l}_lpEYG|y#c!k2LR+mNFA%TV3%l2d)xmJ5sr05@NrZ4m;;mhl2?M(zK1DOt<5%}%N8XMt@~`sm1H~+>WY!ioZ7)B>*qR?'
        'Ryz6_1mp_+l)+v3J>nG>+?Br5sBrs4<%CnkoK=S4T?AvV=d^)Ak_k#h7wy{AuQR$U@wX7&1&aa0q2E|^R}#Oiw?Sb_qAY9UJpc%v'
        'Il0!32Zz0q21IvB80@tjqxT6N*qaK)lEl}4deu<FUWRyoUM^I>4DEXNpkC&nAQsdkOEzM7SAtERv3*9J{c?y`Rx8g^8D+GdmkZTH'
        'arpij(zEo84TX56ye#6C?WJed%p1g;DoU`68ykbRh?fE6@1G&0kC>Y)b#Qo>9ueN{i(W~(k8bMfqPpkiHYLcz6dHXK4L`L!VHb^E'
        '6m#(KuEI|l-euooUwZ*>vvYLY^IX82Do&KMi+0|lQRH=-HY6|-P;hTLgH63$cvqeQcoiKzyer2K?<TQ|vH3>AyNdZuyo~~l%rI}w'
        '*#)E4Vy96Lj&l_c2=CG`oNIeS?-M#W*TkBN#Mfzh)llPHZkLv|Pymq#2luyw&SOww)bK9LIoUbk-MWCwfn8NCLNke$nX17q=V<5g'
        'Bz-)p)CIw=@~lFm1A<-MUWI0Dy#c!>MKo~{V`J48>~c<eb9Xg6Vz)SrgTuSWoS4~{yb`qWy>cU*hGKF_MLR~t1>G5{?zxyI<3@LP'
        '(8=nt&LowMb_PMXo*k}7jP0uL@vgAguJ)}!$L&)zO-fkiOxy+6qEdMMrh^KMR+#mmZkhUZ#&$h>cK<iVc4IInj=r(ju6O5e+&xdz'
        'WF%jq-U53<XtK+?2gkggO}TwtV-V)Gy`uLC9n71NSh|~vHJztd4Greih^YP%hBC0*EdX!T4`$JPVbT)ratHqKu)bKG8`rh>Kimx~'
        'EGh<cN>sPbz7y!;<ACmm>zmgv-(0zyBYJk$cFd*qyj72>15fKA$SJf`d6xeWdRPzZ8?$q!Xs{5tD?|dtu16MvbcL8Ni)|b8Q(VWD'
        'gmxwQ^KouAqt^=Sp5%0tX&ir!lUIn|aZ*Q_#y~=d{+U+Cn#Mqq$gU(un#S>Bv<^BZNOf&9H5ouBXnO)rI>tfto}g-7ZWdwIoN0sw'
        'Rh)*L$xJZ1h^Rf9PcZJs5cohb1k&uAx-*7=&xj!qOj{7cVuvP%kVOXR7MQ3}f{h^vX8D5y8#vv0>QFz3Krjm)Fgxau*q-RMq<aE*'
        'fOoreNZOPT=t4lkkq69n1nZ6;Fxwfl8+yQuU@_i+ncTH;<M+`7e-wc<+rzd!&y6BvQI@s_%miZ`dEKVXvoMMXNqY+-s^kIoqE}+z'
        'z3B6ChO_sgSK<lwqNm52c=lgw;@vIh3D$lqZ?o$x#<&wd5T&7yz3Dt5==@FRY3Qc&^gnOY`8N6^_#)`9zq36ddv~^{Prb7}Aptwv'
        '<0FolwXn+TCvFrfQ%EZx`tmwc9fcB-q3--EiYN}oZ9@*cLNhe#z$-@#lXC`M>jH)vc<p!<ABp}EF{yw7icIG4KZO+zYXRg){Li<O'
        '>0tbi=*#lI&Q7M*Ya9LtT?12+xqe(bXhi@Om#jA@Sjcb!7`~e+7Do_3kL;DGds~v~q6W&^l%OVK{2fhqv>L}Vz@4qf;0*AbJxz~>'
        '(*Av*{sX}AxV+E1u_<mJrVB15c;YUE7fQ7E>aV?}L;NsOQQR9pu962Jeu?xDzjMZqN$~Eb`=tuE)`5qQzY{+X@$>F)io2)jf}u;3'
        'bik^T<x<L#nP0Qn>FLamg)%?Zp<4V%YF1BKcq-;c)mY4r>V3?QRm_i9%#V-E{1^&gej=RtRd~wpDGv9;U{WSlKH%l`r<(jpED`M;'
        'ZANr3WE+(HF+48$qnw>J>$Wc7GUShuk;osTHTjd2m}YLTB#eiVKgLEPf6bPr7a)I3T$cPX+41kvZC&;!lcY6&zVT4Y{v=V1c~*pm'
        'vp=SS*`GX${q<z8MBUevkm{lu&nlY|)@JC@*`L4JID!4`YCZ;Me;l38{*K1edpC;snh`P|mHlz-gT=DL{-lYFJM1TkCdBJ4UG^uD'
        'iTcBSHhBQ{XXMbsew>`o{)~KrVL$$z{q1Cb&HkcoGw)(rg*a}bRWNm>pMd>wc0T*#q3o~A_Vj<+xF6?Zu|F>Mu|Hn1KRw*IpZPrB'
        'hA}@La6AgGkF(Cpt!W?pd03dO@nR{zm$aB)q9b?P=mvCoeW_u7T<bpbV>%eFwU}S^5b3GZkDq-~N+UuLh!f@M(5G|1s(_)mUw<Mx'
        '@ofz1SWx%5>*ZUAy;fXiu4d;ZxI1}vZ3?dly+^?OSkdFiN8SU6P6Zb9(9C_}P6WoCiNI)(`N)DDnz=uQ5Ikt+{uq*o!!!5C5JMg^'
        'jm#B-bcDeBgb24!b;vZv5JCr;#t4!~bl5Zo7UQQ*^DS{}4cbSuali+1zz1@`NAUBJL#stvhEF?BM+Px`Ne`_S8AAvbv|3~gN%-N_'
        'B4dal4w**F@L5L)I*k9xL#8o?5Gu$t#*joGHjRPB=r%_RwaCfo%~21$tGe5pFQdh`wSKg(4ANJ|H%4W=V;_ok7;Z^iov{zBVwSb2'
        'Y|T;a*oUH;bT@&Qn(o?b@%gK_&wrU+zj@(`!6xn7RbyRs*;})$x7Ad%IHzawhgmPpq9DMW7u($Ji!-^QF0WwkuHL_QWy)v4gT=&;'
        '>8;sLqQzpBfE}c>hv>HO();KE`1Eb1`l2P+*g%E(yq#@6&9}*&*_5007cr5|R2N))7EO8iA$Dnbk=%UCfBW+hTE=XilyaN<M_~A?'
        '^=!3VeEHwyv%mfyV<#{#'
    ),
    'deadline': (
        'c-rk<X^-1R(*7%gKWBlyj|KE$Vo&lK@wH<oy8#vucr<5(XrzgxaqL~>zrWQyn`BFBNfgIfTZTtci)<E)Rn^Z^%`X1;Sv+5+^X2Wc'
        'zyJ4HYBtGw{;*xG?KhLnXW4vVW~(gQnC-K_V@3rQ-{n87KSs7eN=&|cwz-Q47tj9wOe?0a=7jTzlT4>bW|Z+%QOOBHR3?ULDoKPh'
        'Eln(?R7RnU>IBgwqDVi3zUKciv-tDYY;6DR&+nf7X4XrynBAEuHEVeL1P5X%kEB8fVN|>r+WR{2bMPxarhOTl#St<H#SG~rB{)_H'
        'v&4SlOemoxB}gJkL?$Hs#Udq0Sp6CJmq`ZShyblfBDpZ|P20bWv5do>B8B}J{BB4tI!BD#cfpiEe7AfV{3oDl6eD7#gKr5Ux#XmH'
        'FJ2mDywDwPYpMQPe<=16odb!!hOtl8k=<1Fj@11Y^84=AAzn1^n<W=K#DFhiBv^-3veY)!BrdL0C4P0?_nUroaiKo~_J*O?yaTN$'
        'uP<l55fzo5Ts!jn8H4`Z-trzPO6|L<`cuWb5QqCqY=2xRo(WO-5_8S~yQhM**>}c`e9#XU33wSrt?N!Z{Y5CCKZ3r!zP-M^MteQ0'
        'VZr=9x;1gMabSv2-#vR+uWr}T{l)^B$d6_ywb-QrGlDAi-Lv^}vt2(X+xco)!I1wxTbo<^J({IvVQ!<XnQhn6gT*0A(ad6kOz|ix'
        'Vun#^8I+g>H1)pb(|qgOPnRLbs5q{Mad*EgnlE4%7~A6mDrt6^FQdgQN|M#%atq+jci0qFhs{b*(-!wWdhkk{4*|KfWdv{Uwg#A1'
        '>=I+dRIHg{l5xO<lmiyzj48l-QFoWsa`72H>^NwKE7fA{Kj^|(6Y%X?pC(qtr&zUj-8|l#^nkLeQP3#i?d5T~Lvox{J2K|m@sIU<'
        '8^vIjJA0sUrEnOkNZrGBeh+9EF7;}C3*yh$zr%h2Kal|tUh0TboW^hsvH}?9Hd5`kd6+L}W@)b#Tu51>T9xqX6E26uB<=3C*+%QF'
        'l~QL}LRqS~NhQyel{&7B3C!dffcL`N_Bs*c*zYBhqMjRIAR&hhT?p;9WI}MyR0-3EY!R@^PGb{PhFBBla)-Hq{~xjkiiH1yGfjL~'
        '6wK9s$v7r|I&{sXKvgmoAxwA#HbA(<2<V!Dh?H>?qZp@zrbK3%XA!3GOKgAw8Tg}QLOXN~n2><(V}G~>sH&WB3tY!)bziuRcZW=}'
        'FJ#8Yhs=0qxD%ECf*19IdVGAiD|VSBt7SG{TT}75d>u4I$<i2a_Ye}ZvU*&pT-gmhv9*aEafjR8<66gQsl@i~I|Eh{)dLGHgGpS6'
        'ka$<%k-GYnmRH9KJh3<Mbi$1!Ss9G{fv06oOv#?TD6PE)L5S>Kal-kbOG>c}xn@+Oy%&YGj@0^vVxL;6q<+1DJ-Xf>!8n0obWs|U'
        'ECIC}2vT6SoMnc@L~|jcNE*;|LI6|6Mr)E`iZZT*WK#LO|4(~>ZMu52m+8ax`}a4$zM1`m@a+1{hnrvjy)2t1Z*N}y`0~xwtI1E-'
        'H*c<A)j#Ch{%~{k`uh8yfB510W&)ybA2(C0;Lnpk=IQosiitv#J2St%+fL!?!zSx_YKmqH1gGdzWfT(#miN(i8sDxzO*Rm>^FTAT'
        'm+6maZT<$AY_nRJ_TgW>{N;LfbM@xO>-Uo!T^9O-ZqqEW_FA@rvZ2kO#JYzSH2JOG(x6N<t>u;&=WX@^HrtuHt?IAbGg(L5<PKU2'
        'J~~-jtGPF`J2>$vn%u6MUh31ejYT&KQDd9ir}pj&wEpAl=KAWzuajg=^W#yA4JP@hvzdws3~nFcgN@IVhr7?4c>*JBJl}4n&~W=0'
        't!?)*voBLBd2K*P$?CyO7pp(4Qa_rdRdlpyAO7b0{q=|0ySFdje1J<Er71YY271e)lyX8Q_hx&yN~e!7Nc^ol-F64BuV25t`E~aC'
        '>fP*@t5+{yOqz`4W{R<@Yyl+Ag?fPNw3%`WacB~4x90v~JH_oTumAP(!|eOFZ$Hf5U*G)l^7-}q+1sDmn>>H_^X%<E-(0`wsBFD?'
        'C@w3{2z;AA<R)S$W6|U`-A-43EKNF@*Ppg<viT>sdop`>^Y(|Aude&bP97d-d9aw`37m-y84L5#Ea1n<^3!bd`0%h=Z%qn6!&kGk'
        'SI~ZWNakt%6^vrBilJAC8OzNgveyN4K3POuIvXWx2GR?mCMJWx0oT!<Oxu3w?8D2~*Eh58ufdAIoqm5b%f#57t=FaCqKo;`Og@_R'
        '#(EhDQj)MKnXK*Bn{5#+rds&=trSuBj9V(mHn*F?zu^q+-_7R@sB2Mt0*f<i_?T^G<wm#lr;;i*4U2SZw@pp_c<U%(wfVFG<F~y$'
        'Of5!DKF_ke$tUjfS8t#H)Cfx^o7LkQKHNQ+tzcCs%1kkyfs!7gc)pl#KSQfl8i)k^6A=uvlLxb&uhLltMqIhFc~~WPvvp*zLmaC~'
        '9?&;aI*A_U$t*Sy*^2Is&E}$_Im&V+6s^z|n2n7O60tmCo4-S>*}zsXzHNS+!Z0=gqxfi=uOA^uuGUjZDz(isP{`v3c7acL^7~`7'
        'm}g+9c_=mak6=@)^~{21ua>UfH9De`bafxibKAJH`T-01IJeef)ic{HR$I`c{djAZW?dWt=MB}4UW2@P{u9Kt<~XeEz8E$#utBRU'
        'p2yXE_?wEzB!~ijHb^Iu!T6>q0SqTH3KW-6LR6v{iA^G78K;1XwMk>e6$bFhBH|O{!_|Ao9(Z%E>(#0lKC;3RRw;z0(%Xw+B_Be-'
        'gx8<zfL{+ERSRhb6lZ7Lv=+1^S7N)VrOeV3t6qypR(hw?FLB$Qo^hwK)wlcQu!cmXAyR3muv)K%l9M$=y&58CYl!X85IsjjS1(?_'
        '{LrXKPKpQs+(MgVvRwT!TiPHY^68+-9gM~^aLDEM@!tMGc&(RJ22eKws<<uoDBI)5)HX%aCS_f<#co>_&0$MiAFghU!NB5KyjUf_'
        '*%8NgBCoDr{Alr8btbBG$tb;_ZvkyUv_XxB*zc9)=AT<ivmg+h`Ei*?>SBY%9Qtu3&RZ>@voO2r1^|Xxf6TuZ$LjA_wmW;4EzZ7o'
        '(PCTtRB6EKwAPCqrSgG&ib7PO`>Mc=D>SOWJ5^C?{!7usK@D8J_~q)&b9ZD%m0{B;;jA`nqVo9|UmvfpUcUPN?Z2EpaAih0$(gTz'
        'w~{;<7^pVe)x$$BW|x~y1N$b`bve85g5k`5bjLwVCpmU^#&>}2<u}YC5vy{8T)Xx+s~yVo38#r!L=PL&YV#fW#mo2au0A~fKj*lt'
        '=Xr4DEFkJfs)H_Bi{BNvmJ`6=GH=lmGh7F(mha?&%7(5zC(?Bw%u5eS=bH!1l1`2%fT>S%qWXkR_a#Rsfx*QaXMt1w{Mz*_(Njiy'
        'aBE|cg0(c`X~AiV(G)hBB$l61FjxCd;>kK&M7Q~8L?&SNn*tHoleCt)M(`87;o^<h4JSEis^_IAIn#h2dGRKSH(9)?;!T&`RNa;R'
        'VN$-+^1bLP1L#=5I)nvJ3C2l8XoLwSJe53Rj4C6!l1U^aHAp7PFlC6LiI6g(MrsoYfw=MpubbD7dS#{FmR6%Y?^C)1mn>6dlf9G-'
        'QQ|Z8NjW|jyAf(<VkS1E#1@#eT5C|=C9lt~-+g%b_D!_`1kj0DuUG3rKkmg%)B0jI7m<nn70<7l*AGA3w1SxGSz5=qf`kgUI1sji'
        '@&+XeQPAMJl}rJUXv)SqJELq<c~XUa;xp~jL50>%MP;Z_`QqiPv|EPT|8|&h(`#eSiHs7(V@YiaSL%o}kt9qSW(0htN*ErQm_{^<'
        'aV!}Oo+6b<XF_BKOO^Nu8H~iQoXe=a77d(h`?xlhO$!yptZvM$TCyBjKbZXfu^CXgIOpc&_llxU=9_i%rTVpGs`-!QXMc42$IsXA'
        '9Y9P_C9S3Yup2PR)x6;TjtUoMdAq%vYBBi;Y&CUQOa7(ELU6{oP1AD%=VB<f+(YcU+lcJ=j!(Ti3HxtTtD5Ehz5Ph$-R%08>o=~-'
        'aF=!4Nf*!_=%!K{EAn^_Pj(0m^TC7U&IYe^N_PxO@7}(7?+i<X^sZa$imV<i=POv5P52^v;U10Sn5{GbYK{+N@g4@>ZT{Iosxb6!'
        '*Q>?UzR#DB-W1N&^XG4WZt05lVw#sAMjQB0=AS03$1TWUrl03#k@}F4*Ox4gtb#m>l|~)_<@2|EKRb%pVA4T@QezYfycQM%p)R*7'
        'k*<S!LjW165-wJ_%agn6G*2Zq)&4^hy&laWd{PbLaQ#$8a|qD_h0+`%E=O~SyeQ2fs^tx(nKw*_*gJn&WA}|o7lemUn#aHv;Zd3f'
        '^Btl?`3^aP@ASm3#H`&;NlMjzzC+8MLfi|0&d7Yn?_u?6o$F|heum^e6raw0jz*$6_dzxH!KY$NT3|~$B(`kE%-vM!64<gul_>E5'
        'OVXlBgeDPA8mdGnBVI3QQzc4L!&sLpm96JfB@B`eOO+@+n<`nM#-~c8FlWb}p3<xxz|JjXFRdG60wLJ`CV<W>^~8jVGOyjYK_G!6'
        'ILNTb3UD$$p`!eJLPbIeRhK~V6Zz7G)@TG0Dk{2!DzojEqf<T^WLJg+dR>nzgX$B@+&Tblj4O!l3iA8o+-xp+N%{<zp?wUOR1BB*'
        '87>-w*)n{X*^+Q(TVh~uP;;4W%yi^~%D%u?Gh0Qe?!bOt=1@Z*_K?h$kx`i~COThCbTYNAJGeNvWwhe9iIlXS!Xp}E9LjAOyBxP='
        '{G!|z5LU|{3PX3eZDLY4r_&g9$!&E%eS?wY!Q7U~P;N_);kI3|D={0#!-O7~%cJE^K@O(I=C(V0tUj-^UCq(ZknEP}liBU@<e|fE'
        '$(Kk6&{MKojyx!zw%KipVu%S1yVXo%pPzKtZ9=jX_1JCEIsm(s$-wNE<MY`q2sJ*trC+o;KNWxF#B13dsFzZT+x%7AWjUksS5D98'
        'uQZgu(kGq}<b&{6&W4{5B*)Sv&iBzJx@SU=j5#65#bMe+kDyHjyz=^zLz^hKEXjkyeEwF^Cdy=9`lCggC{m&5ZAjY0<+!v-6?eX#'
        'PMfL@E>4@cDrplH5SQy)dLim49!i_Iz8q~5=%TbqwCP4^=nZY6LQ?4@3>u>@XcOgv^Nx{g8a^W^NGNM!N3f=z)RmOA-$|zP1&(`I'
        '6DxNL@h?F~XH9+=tIz9fPjfUhBx@4vbk=k<DDAK&`X$0l@+Hg-3hu#}ti_(FP>FQd6Xg<XpTD%(6XP+Ddvk+j>j3O2p#!rgA<kz{'
        'Ak_Hmi4|r|zHGC8Di$TA*TUP#kBUgq7ODd)FQVYMEJ~>JSriLpQLI;b?Kl=ij%88D%{m@j#VB;MTBjU^%ZetUs~AZbN0NJ|lvu@)'
        '=<b^)N$aS?aHM};{p8AsE4)~mbR4OuzSE6rB-9R__PCZLhq)FD=UOEw^Lm`iwGyz?#Dm>@URiT3UBGo0hEhpUDCQfIYe_mP*CJS}'
        'v$$5>!Ns{2T>bJIr<5c$*Mj&XWhmE@{Bm4Nii>hBDck-~7`nr?(g+dP@@u0mxE4cT_g$_fNif%vs<*gt2iM|<S3NeT(UH2Avi7@X'
        '6>Q~rL{}SC;E|UNK@O(9Wb4Q^o98SyYtHEO^=7VC4y@q}B326Z)Ziml)spUS3(byOXr}6MwdE%*hLk3fI(JVp#Qa9yVMvJ~BIz-t'
        'qIH0UW@c!Hq)5-wI>r?w)c?*xv$%YT@>MY-(*AeMyi&voVTl$vQ98rYWIED3%P5O8g-Hx#oC>4}i-1XEA~?<>N@a{Qmf<+oA&f{-'
        'uSIw8nL(LqVJ`-w{}aqBDOO2aVsG*VEi@xv<h+vNU0!tLyb|Ac8(tu1QlfX=j$CL){PRl0;Y{T0c_k%#G0lUD!nsZXioCw$a2-am'
        '=E{SeeEwE(9Y!_l-l;@kj0?tGLy{e(dSvGW92QJ=s`EUR>s0$+tdNG%CB<P(q*=|o8B=+&xgZ*%(d8(P#uueHnzY=YwC{%EFiw)p'
        'B@4AJmlTIn#Cs(*1P<mnnug9Ni6iEddSX{%*8V0qWe4Vyc)3$hNg6ixeA13ILVaFmXA>L^4LP5r`RVgXN2lpK^GWPWOuRb>%wZ;Z'
        'iuoihJlS^9VoQv(R5)chz^9b*`AeHEfv6env8A##lr2%RgO?D5`eex#J13{pB`pIdl=ey$Y^a5_qt7U1DOddItb43!rI$DVaIUQK'
        'T6r7waitQTxQLFck|z5M+aXQZB}stKn$Ko6-%+!(2W+)IoWvIuumw1<2h^6Mp!f6~P|K5;NaYzUeJZFxtw4Dqvpw*0hJ#1hJ)qXb'
        'IzhGZ@=Bc}rtqnxnx6%0s}3%n!pEqZSQ3a~R4+3TaE*hPnLvo@BV0UGsW?P0TPv<EHPABm2IC5p0^D!xzcK9s;|j`%>X<r_NQGC8'
        'Lp(H*FONv%_vEhR+(RlUt~RPhZCN&i`I#6ylkX>x$LI5R5y_#m`WVU6)B1)!Q4IxBjQnKCv}t$b_ueOUfwXD6+#FJ#q^WEHTY)kb'
        'J2y%R$}#r2NPGO3$QC{B0^726h$0Gu*PBE7?0Eny)st6IAWv-A{c;J%R#6yXwg61nYx!+7C@>{y3+Vx<mQQd46~_4d`GS+{D9A7C'
        '>1<({dfXJ*^`+|T74tH9#r&`-dW`Ae9K8(B(U*9~Yrqbj5gfb*d0>&x$ZI+yxazL`pqR5@I5lLB9%D9Yl3qxL&tWsw{+FwEjjK9v'
        'LL^aIXX%BcG&oC-u{edq;K0sLssx9FNeph6f-8;OAu*Ch?z;2Fpi2@XMQ?EvE~YU9Nem9I1*eY4)c54B<gC4pQAFteOua033UV$o'
        'dNH^i>4N&i&dwS*DjKvDHaWc>+$ky04x8cMlA0l@drW-mja8fCNP#2dP#jsV3hR1MhvEpC^jFfCtzTsB9uxXCB=2z&DG}+fD|?R#'
        '^BQ^^5K2iUX;s>m3g!2adu@B@^gSm0aQ<F}<?qX}(R+Rl;FVFDxHqNLL#R&&72s8fscur!K0QQ)j=g&TFL5vs2^*8esQG)2h&T)J'
        ')*W0ve^07M7|GaRRzqI}m^d8z64i&kWGLuM^ktzhMJ=x=&AoxXGT~9;EFNx5yMVq5Gts{dUxy=KibK=)`iS&>PwYy}eSDKv8&w0h'
        'E*pZ}jFPd__kL=5eENPD#T-0+PwC0&`{Q$?K}DjTINOPyG<{E*CyA+B*j57YaPLb|m^0;bk@onnVx6MiI_I+WY;23U_F`L2&%m~n'
        '2j=hhiggUO1#w4D;4>jod!yILc0E>}z71)q@Y;79@~IRIyanepQHbm^>A@i_4Y=1@he6tM(DR<318FtNltP}d(Wiq7(rTuq>ObDC'
        'n9B<qR0q8$g^qitHSkb=R^`*WgUh9HX?3%;#+lUhy(pRs8h$SdLl?xd%yYXn9uUj2_WjnSoi|uk6Jgv(0X8;WU|G#|p7CyBS$@Q='
        'C@lDX>vH}uEREZfyOOi^JIo}~`_s4>QKIdwXF>kOM!)5H2W_m+>}>Yv=xES9F5^#`#}(i5TVaV@=DP_SqZZnQQ7?8gxmpy9(E3i)'
        '#s)f#q$XXsTeg0gsa*C|+=orHM43gUUsWoXDZi<=fnkIV(e0-uB7yQJ9DA*MaOBGZZpOwa4EmNsr1uOR=o|5fW9Au2y;`WSFGh-!'
        '-lM(<*En<#-h+Lq1BPhW^M%K~A6pQ09`>y}xO_gBSNCH_T1s8#b8XRox@!*m!}ZPUmv64zySsS5)=z1LiG8+tsl`g>dMuV<m#?ab'
        '10HifUq*|QE@6G}zxE~cEY!yR3c%++!G;|D&=$=3(2uY=MF??`XV{z~i5&hRHm8W8x{LUaGL7Sx@Oy>mRaiU9G=>pEpnf@nV@+cq'
        'NpM$^BTeIYF<J%hupnLAOic!u)uf>n?*j7|g7%Xmbg1NrU<Z>U_?+a3;4Q#ZBB3TZ5*aRBXykyNWr=1ODdwx)65c|K@cf7np>us0'
        'A2He26TOynUt&^J8`b2Flr2HSxR7H{_w7hR9zWl=GZ{Jfgr88SPxzfMo8qr<{B3?@M@mF!&-@5@o|_VhjLfhz0SLZD+iTovw`sG+'
        'IMs^xrU1*<FLMe|qOV~JP;*8E`bwq%CH9+mJ5i9}C}yoy>2R>(QQlso9y}Ey$>B*rjKfkP<!I<VLnjrIaE@@|8#KLYsB<Ai6NP(g'
        '(-Bv}<L#g~w|VNzUbf^C#pt}6OBACaCj#48Sh9;?;eMt?R*Oaw5lPu(S}4j(JB5fUMuP29UJ$l7Wn_0wn4SgOrEWQQ>9q}PPbAOW'
        'hkH2wS;BUTiV5J(%>5CIQ#{2~cfodY1Z?k#UQ4<!jHqg(8h<dfdxpCgFBBesk-ax$oU+P(N9Y(FwtH%tjtJY?H%zk^wtGvJg6Fxg'
        'J&_Ouoa(#aTM|pJ+q4l*Dk9u}LP^<rIoK}GfbC5&)X`wO93QqD%BZ!^uL8C!?l<u^s7<5T-hA)kRUoID>@w=XVY?Cmu$_d#_Hs1z'
        'o}mNVQ<D&PNoO-?deu<FcE*c4ncA?O5*a++4myXa<fyQn!%4{V)})jjTn4r)H4<#EE3!gpj9C59344#GmO-#xqmf{{#utR`n)G2i'
        '9T2u_+H&sFYa7^ZP)wMMeH;HQVY_{_VE>*2am30R&4OV&Jp#7(MXw~?7e;ioQH?)%*%A~lG#?wb?+6*k!}gt_V{q86#dxq??pjg)'
        '4b$v^?OOUUP5Ytj2Bpk>C_DHT#oX&QZG>a8jHw=MFIxwwmjy^?;CfkFonJ3YiKl-q`(Xo@|FZ_(D~qMI-^Sah)?g$>JKfGCEAAH>'
        'w=fn#=={Q1CqJP5FHjh(h5ZP^7r}o0>RSZut-eK{y80GD0oAwg5szLkL6z4}9QJ2~;0*b&m)DtU_Q#PHr2j-f9*o+CB!2{rTY-x+'
        'D$lz6vF_j^<c}ae4*4TUROC-l&QVSNIKezH0LXF3A3^GJ<c}bIQSwJ{yQV_vv<~@;1!{S5<DSc^);A&Dm1vX*7EJyK4lb*J*)im='
        'Cwe96o-o2twNZ^?McEP*FYxG<6?TM-6Ug7L&@nXmBlwKk3P<B;|01-%05Tqx@)7JSuz=f7k~gu8QfJMX^(f7}&eEoQSrie~s~=Xj'
        '4)H8`>7jh*tT}^G=6uSR$Ri)lIpC7BZ<Mc3`3M$%8}C5bSY@U?RRf{1C?zs7<!g$Go=*8rewsW#l9Q3JhsIxy@?kX=<->X(<*T13'
        '&nwEuN2YuP1yH^to&aA$DX*V6lrO_J1L#9sUT113AB4N^gdYX355{VPQa*ymrF;r2b{6HUI=BqwBV;7XM`%g;GLqOS@S5`JVvTEn'
        'sB9$4NB9LP9}$<Oe5Cy}`_gF}%9l}LOKUq`T)SsQ`83mA%7@tz)kg>kexf}-=8^V&(JM*!hLLKc2E~>wVew-0r`qob87EM_U7=%e'
        '%12Ls$o=s+x<mQoUj`ZTQ7IqwE;!&V%9l~a6ZhskuDRe|XK7PDj7XH?-eYm9<^f2bkps{35lYS{eMUaPJRko?`gW2&O8r*e2D2H}'
        'GHF*B;UE`&0@Bx%x;&lq@lev&C3*U<HqS@-SfsBh(dZ+6ydr&ixOqPFX}%33d?A$??Xyz~!e{%f*&h6PSeUKx0V%JKxP(t9sZM-&'
        '%j-xr;S=E5-E|%eD;|v0T7<7UgY;C!cYcM&Mue~$CsgS3YMhiE3`P0+g=Gl!JS5IBpYC~AU`ri#S$3J*GCK$9m3mm4+$BPfK?07^'
        'qsB)b0|yqaAdDWWGeg|66}VHj0u50;!%q4is53K$5Im^P%ovi0!*yoH5JMg^jm#B-bcDeBgb24!b;vZv5JCr;#t4#dbl5Zo7UPFb'
        '_~y7(s_vuNILHGz$OAdZBl!Htq1r|*!>66IBZC+|r-y1AjUfaJs%<oeB>Zq~qcOw~hfJeo_^cxY9mfCUA=4N`2o+=+V@RS8o5sLm'
        'bi<Kb1MIAD)C2FL9`?TW0)>6mkiKfZGGgPM0TJyLPbG_OW<W4v!agv(;k6B6EvG;v61aPps?a;v_CJ61_W4h<>o+f4DcGcaxN5?y'
        '?t5#NRlQaia!D@0Z)UwTi<}K}s$2OfPsYj3d3gnUclG|gE0fKOZ5)q?7K>E^hLFx4qTAeQ@1qBx*SD4K^T4nvlNRRFcDDIrzD@3m'
        'w0n^r*-UlL%x4h<lKeyLlJvZ}`DTCn{So41Hctw{&HW?r{ndK5S}s2Sd-?3o{|DKyLhA'
    ),
    'forged_irq': (
        'c-rk<YmehLvi&Q@e9i)VKNj$Z&P*qFka=y-B)b7FVCX@08*$qm+dYrF$bY{@Nz{|JX<JrLlJQ{L5-m}sVpZ`RQY!xUSv+5+^X2Wc'
        'fByGbYBtGw{;*xG?ViczvuwUFvsIRD%=XzoF{1*D@A4nkA0t~JB_`iJ+uTKji)a6QmLWni$u&;|izBR5Br+Z;lCqQ|h8g@x5#p4|'
        'I7U&-jY%0pG*y`(GD(wXP}ltb%q;%0H5*$$`{TQ3znS&YEM|8mO3fO+KEs8ezDO#B5Jts^p}n62KL>yEYub;&SsWpQP|T1{Qi5ZJ'
        'FiY$fXF>@rDM1oRA~GT2FBU05!s^e!zf3aNBZ9**L~>zZPustYv5do+B8Br9{BB4tIw+3YZ^4v6e7AfV{3itd#E4kwU@t)=mz)&e'
        '#fPAb7rMi3Emga?J~Y2@=R%^dVeC_NWDixnD|Pome&1a>#E0f}b9TW?4EP~Nf^|qGOKm5bL`6$E@m;&`H+|Q*P#*z%!%%BpL82(H'
        'nlnF$3a6*09r^u?L4D2I>_=0S+Hd9RQ^mIshwDpheOxG>2~qeGYuo{D-U`xY-yPTTK|Nd~;AIrG+MRali%>v)1bzE_`+WP1_IXyp'
        'g86-PYvO3rfGI+K_v~T4x?M;28w+G2KboP`VwW1s2&&k3&*sa`cKw)a=c}cIA^&~0Hn(;^nx$r8ZlkT4ZP(F*#UV=3%wmE}@u-Zz'
        'Mx|v?VjASE&NZLsTi<!Q3^_&tC@Q=0=6P8(U%)BQx5o!mQlBzkMvGaLB&)~e7QmhFvMF+x%}P+y7WY1S@JgF^0lBng1aF_V2AEcy'
        '5@W<vteIhwaZWe|+{Za%is~flp0ZjlzQD$gi)PrV7Hj`S7si@^@6_rxu`0G=)joCecyH1J%5uG+QNmlx<8p`OIB_R3<~#AzdcKWf'
        'Fw31a(AX&)x++rDu$|un8iuA`t#3j6`TBP_58x*<TCq|`oZ>WwHpmKKnA?auZ}Tu;&dk!b6*QzQQLRe2+XBf8D3Er~+H9ls)=H_f'
        'ETJq_+@z9c%1RwOV*)dI2H?H$w!KcoIQDyqq^Rcx7)Z!rLl;7OEtwG9GgZR$AzK8jveVcEl_A!|x!hqc;Qxp0fg<5=aHff`MZsMC'
        'O~x_#qe0hzeF^aX2w}n_umQp)Mm$vpB2vapjAEP;ni835o<$gVnu!fiAOnAtOlXI$0TU8Xee4gn0992Z+yd9JTHP0J<J}>X><gLk'
        '@gXzb8SaGhU+|({P>+ufcf~2QWVOuZYilY#m#>0`C|Mfg?HWR2R#x>Z&Xt>?C$=`RBkpi}dR*x^EtS|leP_T*qN-z|WiW}W5EAbS'
        'JW{)@v}~P5;EBC~rxR`@$;x2l4?Hb%VoLVxMQQCd2ts79#R=z!nv`N0(q>eny^X?JS8Dx2u}`g3Qor879-H1DK|g_^cTpOXECIC}'
        '2vT6SoMnc@L~|jcNE*;|LI6|6Mr)E`iZZT*WK#LO{||eCZMu52&Gg~={rj6=-^_kOcy|5f!_BY%yDW<)Z*N}y`0~xwtI1E-H*c<A'
        'RX^m%{%~{k`uh8yfB510W&)ybA2(C0;4hO;^K^SR#YCaWotfX>ZKu%saL9U|nxfbO!72LejA8=8@;=&5<J<M;$p+$f9%!bvnLb5p'
        '^ABjU&1zxVmw)y0m+RTh)teu$-%oOMS?CX{O|!(>Ygr1)hBAW^>mF9n<hSZbgECQ<mPcZom)Qoak26)7tFJsWSx4LC4oV6>I$2w*'
        'xi_;rxbZ2P+^*_cs@t`NMKuahV~g9j_U;O_{^RWC`s&56lVnZv>rsmhCV8*3nTiQ?ZXaR8#^=ey-IvWgfgU!VZ#PpYxP6S)wtAV_'
        'k13VBHlU+q^<bup)hDaek7j8V9WC0Izqx*Y{bBa*?aMbGplPEt1*h0RZCR93PRQimZ0}a-^btCVf0Vb|uHg0c>$f+*&R$==oBeY2'
        '>g9_`Jz}|;Vyv7kfTX!l5717VDW?#JCee0l?jN>O+^+KaKQBMbzJL4n!|eU_%`Y#XU%#Kd{i%J(^LIbb-v0Z|^^1<m)|-c-S$Rfa'
        'Z~l;*h@mu%Cb#K!y85&<>11AQZQ*9~t!DLP_U`8G4=-O`_m!PIJkIi9F~t+O6B{xX=A&7_kCWx++2--#VYS|x6n=(Xv$QQ}cOH^?'
        'TJ3^SELJhp3Nd53Swyy7K<AT1#AV~4WX(W&A=JcV5ICS6?aj39ht58{e0_a0`~DiN2;AxSN3%?fJ=uC)jY}pU&3a?~3`8ku*py7x'
        '_V~@V2p3Z=d^I~&RCVK)60*(hrtomMNBej4WdjOZ6kA|(W(}L!W>y|_TWytOu`XDoTYGG3;>X*D8djUn8!&%c%fr;7)a1)7%Zq&C'
        'K7aN0`A@a5WU^U3u3_Wu!E6O{!6-9Dj|OUbh~oKTzWoBFT4|sX@J~e0(M}%BdcI0$8JMwiX7jL0?q=)AwuH)(NgmQSQ#y$r=E*EJ'
        'pzxx4a6@ek+!jY!u7si#ssh8Y5kexC583A55N$Sa6!dVL-=@%!O~5QZntJymgvr%<N{Lh3JOhP1Zr~Ky!js=0qs2S}Q_X{^xqk$!'
        'TCHamHhZ;n^{&<tousS#Xr9}~oz)Lm$j7<07OS4wX0h6W9_{9>S(<fm37i+W6TK#R_53G@Z1r_mS$)xQWMG3<S3Hlbc?UQZkx38*'
        '1Z|K`B!eDKQ35DVWE4m)p@gVJF%p|Z#xhO;7i*KoiYpB8lSRZQ#)qr-4SV4Ay{=cQq65haOIW24oJxN$I+nZ>0TW(-sX~6$fw&S<'
        'cPWjNaa~#vlU#}IqLwmCPjs~wv8?pYM!lq2-l!RO3R`tIcMfYvI1Le}p~7mt8cI&q5cO(^oUI|YLqqf&4PCu>{qjStA~`7{01&en'
        'CzIvs(`;#jgwQ!mxP$(91`fI0KHl3O2(R?A$^h&}5R|vY8D)9=nA)OfS`S*gvbb56g6AyeO9MwXc4F9xXYpc{{AT+a-wnLFe(|G4'
        'Ztf0L>55T$Ki>k*fGC4%&#?Q>V)N~mvMl@qCw^S!5xO{FF^77ZlIEor%2|NzssU(W)*tiz;#&Rl%JRmUWl7`QyJ)d3esUVfdr#Xd'
        '<z4v{g{VOHRe)>LuT_9|s-V>PpGE^$FMhdt^Ss%UBWK9eB+xlJL#7aeksoKgzIyrU`?vpT)PbG(<g^B$hLz;OK*zM%t{xt8F}rMR'
        '8dx`R?Q(YA1*e()*zET(o#be}(VqiQFZVFZ;vBr%19I)!-*W9pk~0poh#oekRpz_$i<j@;U43}|KaK0Mp2tDUSpd|JOb1=D62B{O'
        'B`1Kr<+dG%@(5*1ggYpYOtxgtope12^U{UV`R2hAqmu&(!03~_sJ^4qy{V~{1776~tw5lDe%*8`(NjaaA8W&of}+%2XF*_!juQ@<'
        'B$kX(uvGg^;>kK&M7Q}iA``IqP0{(=yR*Ws5&Q&SxcDOW<Vntus!8ZcPAlL?UVMq-OBP?M_|j!HuDY^5Ov-Oseiv0`fD#J?hp^x&'
        '!8nNsjWEH4r;<mEQDr1oGKqww2FXMjrVKGO5mF}9NNpk^5Le!~b@RHRUg^}^(rT0s@|2#y(=<|Lk@W;dk=Mv4WmjCBMi@=Gn%HO('
        'TMW`Ft?+l3sXo7c_u=K+H|_vTfUT|9t97BDX5*%5)tGf7GSP4Gyw$uO_~E7%zf{lCI>r?wRJg@~unx5wlqf_&gX`AF3E)9f7FI(s'
        '$`+M3RoEv!(>@yj(AueRh8mS0UVciuWw`xshZ)zk*5;hZC{a9?)Q;Cm9dRa-gh|7UfL*GD;gN}HL?QOZk|{w&Dv{2F$PAV$@pCWe'
        'gkLq9QF|>K=+*XdZJbRDlM+@HTC3(Iw0<!8!(uaFZE;S+%YDa2C-cp^-f_Q{q%{Ar-1bMefBk&@zJYxSa?)Cs52pcXT+Iub-%#Pg'
        'EN{1WQ!OSRftaQZf|BnP0}h-qZpY*~VUih&EzJ=79xWm}_VKBYB4PhCX|7oAKidyt-p#Imxqj1B8SWBnJHrCn1Kl{Kv0~7!L5UmO'
        'h53*{a%Y2AI;A^0rFU=Nyl-?%g!J02)gr40OYaH-W=D6CZMa9%aLg9tNA>lA7v4j!yUn*7AQk%D?RvGC+VA=D(K}jm_5AtUpIf@3'
        'y_n|Zg3$&x%Auyo>TwG)nCX|fS)@Kt<n<*BAzhHiSWD!=PCkFj&$GP<7D9J`pw#(uM`4(2Vc`$z@~IN#HV|(J79(zO#Y%U1Lg()D'
        'R8r&4zZkV4yredS@(3<eQX4{X{?KL+{UG9U)P~55QX8ULZcy5H&2ET&zL(VoU)yp)atLJ-bxBU~ltmcFAv%=fkRv!wPi!aVK7W($'
        'AP4_wSrFn^0C7g<IDXeUp6Tpzv7z}6#i#R~qtR#1cTmN5@Tqu`7I=~li6`rRayLD?1fFcsBT77AlC<a%VVIHzJt9<K?emW|J)#uH'
        'ly&J*S$aM_0+|M;N0gpTkE~GR(<4%tbHkpV(ySXGom-e*S~tdofT6%|0w}yvPfVgH^V)qI_(2OH(;`uX+D8yaCsCB2PohXDiRzLj'
        'ej-P@&`TJBB#MeIiOOvG<tUU-2HBM%fm+w&%AopWGPe%E8RH6~yMp}wI5(S1Hc6k=GPIA?631$JpVgu<*et_`*(?cXvnBlX2DK)e'
        'jVX_n2POLgU&Uq>(Y%BBnaaUp7`h&k%`!47o5e&5c@CYeD!3S*Wz_N6L`7Uxd{$#2L-{OYm*caHUzE=Rv}!p*Vc`uvn`As`62r=x'
        'OFpYv!G@ZA7PIg<J0?T<EIo$LcExsL?)5l#P=(jaf*{XQWAoV^&UHMY-RWdQGg_ukX0*o>h7O}8Un2!TPswOG@*sQKX0$0LQPN<v'
        'nir4tc0HuSXcMYXpV1bj129^d49sXbKA+KoP~$UN`c<3rQ*l;Kyq4X8cPU9^o3m=Jo?zmS)AKni4dtx#i6{Q}Ae@!6;V1scu@s5('
        'eH4lAnfN1PPW*9km@3gDs8WHfyuQ?+N|dQc_yCyC-yBt<jN$I&2(wR)hXS`DsS=mtQY9(#EEK0xC0D`4sFHn#r)XTR<FtCJk#dYt'
        'C{^P6a#Ts6i&7=grWmD#*HnoLl<<bh*VbH6B?!w}b*x(}70i?b31v#`2&UAN+DW<3;gmbb;XqavggBO<qcbJHZ=JxDcKO)QOi8fQ'
        'nbOffw8NC>*9a}i*DwbtxCd9V7Gt7<D9LKZM0sb9+<8iyF)_}J?lGpabO6Sb(196~5a%-{5NdqJ#0s+}U$<F56>}2OYvFCQM+GBM'
        '3&~L+9ddl;B-HuLiG?yJ*2|%G9CISaGN<Ea7Z1LSD0KZ2PTBvKsYya#MkHapNba3FVvZNl-48^P)>Vh$MgP9~sVO6NP_Z=Wn4)^{'
        'pDMX?@W02eBst8lSUA5b@tD`+n*1u(EKWSI&F7UBztSkru-HVP&|!&SxHlxfl5|vlMKI0t^PSAEstPW~uK+i=ky0g8ZH-zm8p^LE'
        'zZ}1k;-dUY%C;jE7T(}jNyc%LsZ`cn@+++iQ*QDrM1uL1RK1rKcknBI_$|izHhNO)0Ecr2Rj9En2y!g#<yS|(gZWo`drYC88hnh('
        'y^{Uy?XlzD9#d6^+VYbYHA*puR;Z|v^<C{V@(wjhsN{WWRFn?z_Lv!(8Y$AVw2pBF3H8@`dn_(LqWm~YMB4w3nM8^>AuQ1XCrW2n'
        'noLKUXBlO2rZ9=AP=KQpVG-joCW7NEqEyB>V;PQP9YTc^^;&cXn58U>Ta!o(St}o%3MuBKEkQT=iryY0U*#l{;$1>?<RlW`_nciI'
        'SyH0cZb!a7M*NdVq(PR**^@|0_F|d`6@`<W0u*_DsX=lWHqhoC?Bw$|M{*d&to!yDC4>fJt|3W|QazG$0uBo%Iqp7B<v8yAi%}e<'
        'ONzrN)k!slWY<LqPK=?^<tUEE7o|9wwA`Sy@0#K;8ms1HOl`{r#R0&^yHiM*<R~hP<7gT>ha`@eL+Xj`#N6j^+8yNJA1@1na?G%?'
        '=a6=c9~@70c8((q&3H6FeGcj9q4~}n68jnl+Zz|m5hi(xIV3GSBkZC@lo&9jxbYqtW2^|vT~BEfB~G%aKZjJ7h7u)8cFoop&ue5D'
        '5iL(=N?Ha^BJGtb*iZ{;|AMnfy9|4*S)`XY|7tX<@)~#>>v4%vl{9f2l#rb^-JnXiNsR!N)!Sw@-;rsv2WPcDJZ3K(oV7_lcSG5-'
        '@AKYX1IhvoWl7@cB7G`wP?l>Udfh#z7zOvOd$24%7R%-dHb)$>r$WfHM(nE!E|}-dO(1cTrdgE@L68Esg(YJ{<bs*r5WQ@wH^f@*'
        'P}+G7X?ey`^FhGcrVB_bNdE;AA|(q?`i6MuxV=1L+`cP!CFdT$qnLEwAdw{e4HAsR*aP=|zIZ&Q-NhRRPXUMI>7)3DK2c5tQgr!b'
        '$WhX6m+yTZ>H?#r?UZpydB#X(3(WFNWKrXRC_y;!x=6d@7e<q)2WHFCA(A2to-+>VvxohyR8O82fjqHc_tPI7n-yV%$pMU!*YZ0s'
        'FpD*A%?=163-mVb>;T62{ON&{^CHNvYdN*Bfq7i#$n}lPS8u?};5Xoh9g)YF9v+gH;Y0Ez-tii6gU1MljP$`GpOHHrBY?qn-|GOo'
        'QNeI($RT-**{Eakg3_~Cj645wBnG>bZV(C$uLk9Xuo)17vsIsz(+vk!eo|65986+xJF8o1<TZ&AT(h__5mg&>Nn!-=%{gfuJ}i%M'
        'a8@^U#JGG<Y$xVkr*j8Y0Ie(taxOA@TDKj;1SgP~UBd-~vlw!EX17xYJUcvwe;dL)#A}G}1!C3WH3G1sZVb``ux$_0JGW``8p%?T'
        'p)Ri}OM`h0tq6o2JZjrV;vJ?xi`tOjgm3!=JH~MTn(uo&wVC&L3}IeNZ^J;r6HeL?4`L;~IFIRrUcwI#+$#rq8;f)~+-ui9^mUQm'
        '`)$Hr9pUEiebtltbW*`yO;Go7d!U;<xCd^*UMsp?VePcBdm_#qyDzUF)Fo@`9^^c6<la><6zKhMee*hBg0Z0y&*WpzZd$kQI#3b#'
        'fSDcW8922bIXashCVJ@HdM5}$(M6K$ogxVyKD*v2Vvz2`hew&l@sA#Qg`iy_jxvpbgkb&0Fpo8jfh6fY5PGC(952T6_OeO6RGg_@'
        'pmGhd=bZHd`;4Euh1P@-Y5k^=EE5_ANUAO(X`lI1eZgS`b~s@KK4(~gb?A5jA{xUA8AhUsDk{KG3@b<?Melt*F3=GRVv*3fQGLYR'
        'Xjkq^&V8tcxPu%)Qe{C9eqnU%xl#YP-SNW;yT<PZA5~!N<hjw~C!T_`>pk&Q5_;0P(K>Nw%gb702pQ3$kzP*{MU>A)I%5ci+pK)u'
        'F@&P@{0IHG_CM%H&lo{qB5-nauUJP7e9`e|M;SIL%0{>Au_i%VkNIIHz4qN^(lV1EK$9ga%Cz2P(nCMzhnYG&Nv6Xd^ea0(@BKAK'
        '3KS*OAWz@u(}5c)P+Sw-Tlx}n8QiG`KIn(TI$J&J3>nr;sk2g_xeA6FE@*>Yjz)sz+&xXG7-v~E5vPRQ`5JpiQZf=OuX9#j0G4ys'
        'hvj%cSk8HSdD_BbYgn$BNm&El*4|mbawU=O=e(BTYdB#pLScFNoJkli?+NY%-4{ZrJIH|!T^59`R4d2E<vXIq3CY}cMUBCcIajA6'
        '^Ali?KcCw-AhQFgbL{~#7`2eP;wVlUPcbTq+iBgL)3jlYW+YQRq+XVOok(4vzXMWNiX}4rn;><8{RZBKvRa^sw4l0H<?_xxn;smh'
        '3vw8$V-$wf%Z|`{gAJ^%6UI|tf9X?#!|GtMwBP;nA{|^<PrC=KlLqD?K|Qdb<Gy0f<auDds^BtUU9geBx^Pd;=`^!>ZA!3?5s<sE'
        'L3ANTLhE%_#|xl!q55c@42af+Zn<{pvo%`RCWS!RSYo*L&jPMv#E_C*hZUNK<8_IG@j5;NulGfFlI{y5+#Tew2gYSdP`r?M^tX)s'
        'A>)K6^mc`g!4bP8Pl?#sH$bx&u}fcSCh)u_V%H`E*jOWW@GUH~*KOMPCNkJi)y3>(>E$r{8L!b}$wtTQa(v95N{Q&-WprI~zlpaY'
        'ZA^%1uVI6sv*&1+Q4bE<r3e7+I1IFxy`lFG8=yVrY1UlYt?o3vYN%j4*0{g&I!B5I_qTgsJ8gg;8rBWVQDHmN>b#ffs|qdy+oc)_'
        'wo8|RDwfRX8nzP%lsX8uD>M>pSNMXkz0OkEu-pM*yP_@UF1@yf?Xk>w(wHY}_~+8)wJOtBw<g6z_|lSCv0&Ivj)3hw(JM*!g%Rlv'
        's_+LbOM>Es;$y@19U<d**uFD#3=Z3s7!S7Ze6i*mrr818mG6lG@Vq8$j}_*kG0+aaC9v|kO&j4Pk}A}Dv8F5?AYlNQ*1!n^lsZ3Q'
        'fD%u?=;T2IXXr0$;Jx>0l=j<r2i3xrbZe{~>|7%H1epOeIzKbO$*WKP2{Hq;v7g2l!G50f1A1@z0s7?W2XsLC0ZhX450s$F>nBb2'
        'mqbaTeAvtDOcnbhRFE#1q&eUZL~VnTKRs>=0#5XKYoAmVT!#E<J`(wZ@Ku^oYP4oG`Lin_garUO68WpsC|-d4X?;=hM-XcJcHy)Q'
        '@@EuJn`1b&dph#R6zyj^#^KLc0iO>hfAkpg*Av}Ix;KotgK898mW0F$yQav<<ZnmFIG+6N3>`z0KZ5A#<nL%4-JyQsPlJp{rF;Z2'
        '9~`D_%4Z^rLK~Ei>Gr}fm9umxUz#Y~%Mn+W4zXya^iV!@2IV83RFy|lzC<3g7}2m<6uwcuKIOAI_S$#{%9?~E?Wr2DbIr!5e56jI'
        'c{=4gdD%>UBqt+bt7Be_@)4v)qI{&zAnBug)xw$FQ9eE{<s%pcP(FGD<tw0+*H0RhFOfJl$cMPR&Qwu8ikRRX2+2#B8HCk_q<jEf'
        '$EAFVpZAzvRl!9lAHifC%15k07G|WBs*~Gcig&MA-w~CKL-`2im!o_Hi_20z++Mx2blRHoC7MXy^y1n*m+pNxg?MkikA=VOPH^xF'
        'o|qj$`TC+eN%w^j<qoP)EGtXG;>GBzc<u-pCs4j!p<{5$M^0bV^LQNHp?vaBgN*s8l#h7dHefBvmuN<!M)ExCQPS@$ZOWG_p>=PT'
        'uPhya@)<esEFU4~uLf$R8h@6Lf1`XmDIcMJ8*f8d5Q4EbN~O3Q4I7#AkpY$m<)M_XOY!udY?hA@J{IL8dzb&@j`Hc@X8FwL`8JI1'
        'k$^Qni{Up*_iVit*MmO~3$ryo80GbmCfzeQNtF+6c^#>ydmM4zTlbTrV4T*Xd+rX>Q~4e_d*#nsgrIaqxEdloG0(WG;Bq+^3Gu9v'
        '(J-IxeLJY74!bP9%tM)-i{Ng8xV6b$BJ>(0;2J$*eB?E7V7fa}XaC!kosu+@-QiBMJ2XVjJwn-`?37~&!Gp3>jv<LSoSkwEG2|iB'
        '$eKcsju3dC5aITz4w=RnLg*mV7(o(-4x7fnV*Jnv-we0XE`Kze2J%1+<bfK<Bl!LfW<+fnKJDBc8N~3}!HlS52oaVMbqq-YGNO(l'
        'hB#yzEyHIWA?PsvCl8s%7(%EZ(-=b%eb_Vx7NZ-E>bzX!yl~V5@4V{v=F4dD_e+=FR|x4V<Zni2yt5v>{gzY7UF%toRO&cxJ}p+W'
        ')N<B?VIsQ^x`|>rO)pt^_4fHsv+Fl6nnJKi>uPR_tEzfymL>ni2;(AQ;BRKVG>d#GVr1WhMtet@n&Vtvx!zs9f8P{|10}KMQm4|7'
        '7K>E^hLFx4qTAe6@1qAG)wfRfc{tdVLlx%pcDDI6-zIm(i#5fd$Y!c@K0b@=`>S>%Zc=k7Zp@wKzy1CQ(J`ARh3Mw~5m^3eJzFgo'
        'U;cOb?2rEkrS8$b'
    ),
}


def fixture(case="preemption"):
    value = json.loads(zlib.decompress(base64.b85decode(_FIXTURES[case])))
    return value["stdout"].encode(), value["binding"]


def change(data, marker, occurrence=0, **fields):
    lines = data.decode().splitlines()
    matched = [i for i, line in enumerate(lines) if line.startswith(marker + " ") or line == marker]
    index = matched[occurrence]
    words = lines[index].split(" ")
    values = dict(word.split("=", 1) for word in words[1:])
    for key, value in fields.items():
        values[key] = str(value)
    lines[index] = words[0] + (" " + " ".join(key + "=" + value for key, value in values.items()) if values else "")
    return ("\n".join(lines) + "\n").encode()


def pair(data, occurrence=0, **fields):
    data = change(data, "TESSRYN_K01_EXCEPTION", occurrence, **fields)
    return change(data, "TESSRYN_K03_TIMER_TRAP", occurrence, **fields)


def renumber(data):
    count = 0
    lines = []
    for line in data.decode().splitlines():
        if line.startswith("TESSRYN_K03_TIMER_"):
            line = re.sub(r"sequence=\d+", "sequence=" + str(count), line)
            count += 1
        lines.append(line)
    return ("\n".join(lines) + "\n").encode()


class TimerTraceTests(unittest.TestCase):
    def bad(self, data, binding=None, case="preemption", code=33, stderr=b""):
        if binding is None:
            binding = fixture(case)[1]
        with self.assertRaises(ValueError):
            parse_transcript(case, data, code, stderr, binding)

    def test_complete_original_diagnostic_protocols(self):
        for case in _FIXTURES:
            with self.subTest(case=case):
                data, binding = fixture(case)
                observed = parse_transcript(case, data, 33, b"", binding)
                self.assertEqual(observed["requests"], 14 if case == "preemption" else 9)
                self.assertEqual(observed["policy"][1]["state"], "completed")
                self.assertEqual(observed["final_allocated_pages"], 0)
                self.assertEqual(observed["clock"]["tenant_ns"] + observed["clock"]["kernel_ns"], observed["clock"]["end_ns"])
                self.assertGreaterEqual(observed["spin_irqs"][1], 3)
                self.assertEqual(observed, parse_transcript(case, data, 33, b"", binding))
        preemption = parse_transcript("preemption", *fixture("preemption")[:1], 33, b"", fixture("preemption")[1])
        self.assertTrue(preemption["pending_irq_probe"])
        budget = parse_transcript("budget", fixture("budget")[0], 33, b"", fixture("budget")[1])
        self.assertGreater(budget["policy"][0]["consumed_ns"], 80_000_000)
        self.assertEqual(budget["policy"][0]["state"], "failed")
        self.assertTrue(budget["policy"][0]["halted"])
        deadline = parse_transcript("deadline", fixture("deadline")[0], 33, b"", fixture("deadline")[1])
        self.assertEqual(deadline["policy"][0]["state"], "deadline")
        forged = parse_transcript("forged_irq", fixture("forged_irq")[0], 33, b"", fixture("forged_irq")[1])
        self.assertEqual(forged["irqs"][0], 1)
        self.assertEqual(forged["spin_irqs"][0], 0)

    def test_process_completion_and_stream_bounds(self):
        data, binding = fixture()
        for code, stderr in ((0, b""), (33, b"failure"), (None, b""), (True, b"")):
            self.bad(data, binding, code=code, stderr=stderr)
        for bad in (data[:-1], data + b"\0", data + b"unknown\n", data.replace(b"sequence=0", b"sequence=1", 1), data.replace(b" task=", b"  task=", 1)):
            self.bad(bad, binding)

    def test_unknown_failure_or_foreign_markers_are_not_ignored(self):
        data, _ = fixture()
        for marker in (b"TESSRYN_K01_EXCEPTION_BAD reason=x\n", b"TESSRYN_K03_TIMER_FAIL reason=x\n", b"TESSRYN_K02_SERVICE_PASS\n"):
            self.bad(marker + data)
            self.bad(data + marker)
            self.bad(data.replace(b"TESSRYN_K03_TIMER_BEGIN", marker + b"TESSRYN_K03_TIMER_BEGIN", 1))

    def test_compiled_descriptor_program_and_loop_binding(self):
        data, binding = fixture()
        mutations = []
        for key, value in (("sha256", "0" * 64), ("size_bytes", 88), ("efi_rva", -1)):
            b = copy.deepcopy(binding); b["descriptor"][key] = value; mutations.append(b)
        b = copy.deepcopy(binding); b["programs"]["a"]["sha256"] = b["programs"]["b"]["sha256"]; mutations.append(b)
        b = copy.deepcopy(binding); b["programs"]["a"]["offsets"]["timer_a_spin_start"] = 0; mutations.append(b)
        b = copy.deepcopy(binding); b["programs"]["a"]["instruction_bytes"]["timer_a_forged_irq"] = "cd80" + "00" * 14; mutations.append(b)
        b = copy.deepcopy(binding); b["programs"]["b"]["instruction_bytes"]["region_b_stale_unmap_trap"] = "4883f800" + "00" * 12; mutations.append(b)
        b = copy.deepcopy(binding); b["kernel_header_hex"] = "00" * 64; mutations.append(b)
        for b in mutations:
            self.bad(data, b)

    def test_startup_source_memory_and_cpu_admission(self):
        data, _ = fixture()
        for marker, fields in (("TESSRYN_K01_LIVE_RANGES", {"scratch": "0x0"}),
            ("TESSRYN_K01_LIVE_RANGES", {"image_end": "0x100000000"}),
            ("TESSRYN_K01_PAGING_READY", {"physical_bits": 52}),
            ("TESSRYN_K02_PROFILE", {"cr4": "0x40668"}),
            ("TESSRYN_K03_TIMER_PROFILE", {"fsgsbase": 1}),
            ("TESSRYN_K03_TIMER_TASK", {"root": "0x1000"}),
            ("TESSRYN_K03_TIMER_TASK", {"stack_physical": "0x5000"}),
            ("TESSRYN_K03_TIMER_TASK", {"request_physical": "0x10000000"})):
            with self.subTest(marker=marker, fields=fields): self.bad(change(data, marker, **fields))

    def test_clock_hardware_profile_conversion_and_conservation(self):
        data, _ = fixture()
        for fields in ({"period_fs": 9999999}, {"source": "tsc"}, {"base": "0x0"},
                       {"capability": "0x9896800086a201"}, {"apic_after": "0xfee00900"},
                       {"pat": "0x7040606070406"}, {"master_mask": 254}, {"kernel_if": 1}, {"user_if": 0}):
            self.bad(change(data, "TESSRYN_K03_TIMER_CLOCK", **fields))
        for marker, fields in (("TESSRYN_K03_TIMER_ADMIT", {"now_ns": 0}),
            ("TESSRYN_K03_TIMER_ADVANCE", {"raw": "0x0"}),
            ("TESSRYN_K03_TIMER_KERNEL_GAP", {"elapsed_ns": 0}),
            ("TESSRYN_K03_TIMER_CLOCK_END", {"tenant_ns": 0}),
            ("TESSRYN_K03_TIMER_CLOCK_END", {"kernel_ns": 0}),
            ("TESSRYN_K03_TIMER_CLOCK_END", {"generation": 1}),
            ("TESSRYN_K03_TIMER_CLOCK_END", {"pending_after": 1})):
            self.bad(change(data, marker, **fields))

    def test_exact_initial_and_resumed_context_reply_boundary(self):
        data, _ = fixture()
        for fields in ({"r0": "0x1"}, {"r2": "0x1"}, {"r3": "0x0"}, {"rflags": "0x2"}, {"fp_sha256": "0" * 64}):
            self.bad(change(data, "TESSRYN_K03_TIMER_RESUME", **fields))
        for fields in ({"rip": "0x100000000"}, {"r14": "0x1"}, {"r11": "0x0"},
                       {"r12": "0x0"}, {"r7": "0x0"}, {"fp_sha256": "0" * 64}, {"resumes": 0}):
            self.bad(change(data, "TESSRYN_K03_TIMER_RESUME", 1, **fields))

    def test_actual_raw_exception_adjacency_and_exact_frame(self):
        data, _ = fixture()
        self.bad(change(data, "TESSRYN_K01_EXCEPTION", rip="0x100000000"))
        lines = data.splitlines(keepends=True)
        raw = next(i for i, line in enumerate(lines) if line.startswith(b"TESSRYN_K01_EXCEPTION "))
        self.bad(b"".join(lines[:raw] + lines[raw + 1:]))
        self.bad(b"".join(lines[:raw] + [lines[raw]] + lines[raw:]))
        self.bad(b"".join(lines[:raw + 1] + [b"TESSRYN_K01_EXCEPTION_BAD\n"] + lines[raw + 1:]))
        for fields in ({"cs": "0x8"}, {"rflags": "0x2"}, {"rflags": "0x302"}, {"rsp": "0x0"}, {"cr2": "0x100004000"}):
            self.bad(pair(data, **fields))
        for fields in ({"root": "0x1000"}, {"ss": "0x10"}, {"frame": "0x1000"}, {"trap_end": "0x1000"}):
            self.bad(change(data, "TESSRYN_K03_TIMER_TRAP", **fields))

    def test_actual_request_bytes_caller_status_and_user_read(self):
        data, _ = fixture()
        first_bytes = re.search(rb"TESSRYN_K03_TIMER_REQUEST [^\n]* bytes=([0-9a-f]+)", data).group(1).decode()
        for fields in ({"caller": 2}, {"pointer": "0x100010000"}, {"length": 88}, {"request_id": 0},
                       {"bytes": "00" + first_bytes[2:]}, {"bytes": first_bytes[:160] + "05" + first_bytes[162:]}):
            self.bad(change(data, "TESSRYN_K03_TIMER_REQUEST", **fields))
        for fields in ({"status": 5}, {"value": "0x100000002"}, {"charged": 2}, {"control": "exit"}):
            self.bad(change(data, "TESSRYN_K03_TIMER_RESPONSE", **fields))
        # Coherently alter both frames; the source-bound actual read result is
        # still required at A's second request (before its writable unmap).
        self.bad(change(data, "TESSRYN_K03_TIMER_TRAP", 1, r12="0x0"))
        self.bad(pair(data, 1, rip="0x100000000"))

    def test_timer_arm_irq_source_and_pending_cancel(self):
        data, _ = fixture()
        for marker, fields in (("TESSRYN_K03_TIMER_ARM", {"generation": 2}),
            ("TESSRYN_K03_TIMER_ARM", {"target_raw": "0x0"}),
            ("TESSRYN_K03_TIMER_ARM", {"readback_raw": "0x0"}),
            ("TESSRYN_K03_TIMER_IRQ", {"isr_before": 0}),
            ("TESSRYN_K03_TIMER_IRQ", {"isr_after": 1}),
            ("TESSRYN_K03_TIMER_IRQ", {"irr_after": 1}),
            ("TESSRYN_K03_TIMER_IRQ", {"eoi": 32}),
            ("TESSRYN_K03_TIMER_IRQ", {"generation": 1}),
            ("TESSRYN_K03_TIMER_IRQ", {"capture_raw": "0x0", "capture_ns": 0}),
            ("TESSRYN_K03_TIMER_CANCEL", {"pending_probe": 0}),
            ("TESSRYN_K03_TIMER_CANCEL", {"pending_before": 0}),
            ("TESSRYN_K03_TIMER_CANCEL", {"pending_after": 1}),
            ("TESSRYN_K03_TIMER_CANCEL", {"isr_before": 1})):
            self.bad(change(data, marker, **fields))
        self.bad(pair(data, vector=32))
        # A later ordinary cancel cannot claim an IRQ0 pulse while even its
        # final actual stop still precedes the current comparator target.
        self.bad(change(data, "TESSRYN_K03_TIMER_CANCEL", 1, pending_before=1))

    def test_nonspin_irq_preserves_every_captured_register(self):
        data, binding = fixture("forged_irq")
        lines = data.splitlines()
        irq_trap = next(i for i, line in enumerate(lines) if line.startswith(b"TESSRYN_K03_TIMER_TRAP ") and b" vector=32 " in line and b" task=0 " in line)
        raw_index = sum(line.startswith(b"TESSRYN_K03_TIMER_TRAP ") for line in lines[:irq_trap])
        for field in ("r0", "r1", "r4", "r8", "r12", "r14", "fp_sha256"):
            self.bad(change(data, "TESSRYN_K03_TIMER_TRAP", raw_index, **{field: "0" * 64 if field == "fp_sha256" else "0x123"}), binding, "forged_irq")

    def test_spin_heartbeat_and_actual_interrupt_count(self):
        data, _ = fixture()
        lines = data.splitlines()
        irq_index = next(i for i, line in enumerate(lines) if line.startswith(b"TESSRYN_K03_TIMER_TRAP ") and b" vector=32 " in line)
        ordinal = sum(line.startswith(b"TESSRYN_K03_TIMER_TRAP ") for line in lines[:irq_index])
        self.bad(change(data, "TESSRYN_K03_TIMER_TRAP", ordinal, r0="0x3"))
        self.bad(change(data, "TESSRYN_K03_TIMER_TRAP", ordinal, r1="0x0"))
        self.bad(change(data, "TESSRYN_K03_TIMER_TRAP", ordinal, r11="0x0"))
        self.bad(change(data, "TESSRYN_K03_TIMER_TRAP", ordinal, fp_sha256="0" * 64))
        self.bad(pair(data, ordinal, rip="0x100000000"))
        self.bad(change(data, "TESSRYN_K03_TIMER_MAILBOX", spin_irqs=3))
        self.bad(change(data, "TESSRYN_K03_TIMER_PASS", irqs_a=0))
        # Alter all spin counts coherently while moving their actual RIPs out
        # of the loops. Kernel status and an authentic outside IRQ cannot stand
        # in for the required in-loop execution/preemption witnesses.
        modified = []
        for line in data.decode().splitlines():
            if line.startswith(("TESSRYN_K01_EXCEPTION ", "TESSRYN_K03_TIMER_TRAP ")) and " vector=32 " in line:
                line = re.sub(r"rip=0x[0-9a-f]+", "rip=0x100000000", line)
            line = re.sub(r"spin_irqs(?:_a|_b)?=\d+", lambda m: m.group().split("=")[0] + "=0", line)
            modified.append(line)
        self.bad(("\n".join(modified) + "\n").encode())

    def test_policy_reservation_selection_and_full_actual_charge(self):
        data, _ = fixture()
        for fields in ({"grant_ns": 1}, {"hard_ns": 1}, {"soft_ns": 1}, {"lease_generation": 2}, {"task": 1}, {"cpu": 1}):
            self.bad(change(data, "TESSRYN_K03_TIMER_DISPATCH", **fields))
        for fields in ({"task_consumed": 1}, {"domain_reserved": 0}, {"cpu_owned": 0}, {"task_slot": 1}, {"halted": 1}):
            self.bad(change(data, "TESSRYN_K03_TIMER_LEDGER", 2, **fields))
        for fields in ({"elapsed_ns": 0}, {"capture_ns": 0}, {"lease_generation": 0}, {"outcome": "complete"}, {"state": "completed"}, {"irqs": 1}):
            self.bad(change(data, "TESSRYN_K03_TIMER_ACCOUNT", **fields))
        budget, _ = fixture("budget")
        for marker, fields in (("TESSRYN_K03_TIMER_ADMIT", {"budget_a": 2_000_000_000}),
                              ("TESSRYN_K03_TIMER_TERMINAL", {"state": "exhausted"})):
            self.bad(change(budget, marker, **fields), case="budget")
        # Forge a capped final ledger while leaving genuine observed clock and
        # full elapsed records intact: independent accumulation rejects it.
        capped = re.sub(rb"(?<=task_consumed=)8[0-9]{7}", b"80000000", budget)
        capped = re.sub(rb"(?<=domain_consumed=)8[0-9]{7}", b"80000000", capped)
        self.assertNotEqual(capped, budget)
        self.bad(capped, case="budget")

    def test_deadline_readiness_and_forged_interrupt_are_actual(self):
        data, _ = fixture("deadline")
        self.bad(change(data, "TESSRYN_K03_TIMER_ADMIT", deadline_a=100_000_000), case="deadline")
        self.bad(change(data, "TESSRYN_K03_TIMER_TERMINAL", state="completed"), case="deadline")
        forged, binding = fixture("forged_irq")
        lines = forged.splitlines()
        ordinal = next(n for n, line in enumerate(line for line in lines if line.startswith(b"TESSRYN_K03_TIMER_TRAP ")) if b" vector=13 " in line)
        self.bad(pair(forged, ordinal, error="0x0"), binding, "forged_irq")
        self.bad(pair(forged, ordinal, rip="0x100000000"), binding, "forged_irq")
        self.bad(change(forged, "TESSRYN_K03_TIMER_MAILBOX", b_read_confirmed=1), binding, "forged_irq")
        self.bad(change(forged, "TESSRYN_K03_TIMER_RESPONSE", 5, status=5), binding, "forged_irq")

    def test_owner_revoke_quiescence_deferred_charge_and_zero_cleanup(self):
        data, _ = fixture("budget")
        for marker, fields in (("TESSRYN_K03_TIMER_MAP_EVENT", {"frame": "0x6000"}),
                              ("TESSRYN_K03_TIMER_MAP_EVENT", {"lease_generation": 2}),
                              ("TESSRYN_K03_TIMER_CAP", {"phase": "release"}),
                              ("TESSRYN_K03_TIMER_FINAL", {"charged": 1}),
                              ("TESSRYN_K03_TIMER_PASS", {"cpu_leases": 1})):
            self.bad(change(data, marker, **fields), case="budget")
        lines = data.splitlines(keepends=True)
        removed = next(i for i, line in enumerate(lines) if b" phase=quiesce " in line)
        self.bad(renumber(b"".join(lines[:removed] + lines[removed + 1:])), case="budget")
        # Even after both DATA PTEs are cleared, the live B child still prevents
        # A owner release; a self-consistent terminal label cannot refund it.
        replaced = data.replace(b"domain=1 phase=deferred cap_slot=2", b"domain=1 phase=release cap_slot=2", 1)
        self.assertNotEqual(replaced, data)
        self.bad(replaced, case="budget")

    def test_coherent_irq_resume_into_known_fatal_code_is_rejected(self):
        data, binding = fixture("forged_irq")
        lines = data.decode().splitlines()
        irq = next(i for i, line in enumerate(lines) if line.startswith("TESSRYN_K03_TIMER_TRAP ") and " vector=32 " in line and " task=0 " in line)
        resume = next(i for i in range(irq + 1, len(lines)) if lines[i].startswith("TESSRYN_K03_TIMER_RESUME ") and " task=0 " in lines[i])
        offsets = binding["programs"]["a"]["offsets"]
        for offset in (offsets["region_a_fail"], offsets["region_a_fail"] + 2,
                       offsets["region_a_exit_trap"] + 15, offsets["region_a_exit_trap"] + 16, 4095):
            altered = list(lines)
            for index in (irq - 1, irq, resume):
                altered[index] = re.sub(r"rip=0x[0-9a-f]+", "rip=" + hex(0x100000000 + offset), altered[index])
            self.bad(("\n".join(altered) + "\n").encode(), binding, "forged_irq")
        bad_binding = copy.deepcopy(binding)
        label = "region_a_exit_trap"
        instruction = bad_binding["programs"]["a"]["instruction_bytes"][label]
        bad_binding["programs"]["a"]["instruction_bytes"][label] = instruction[:20] + "90" + instruction[22:]
        self.bad(data, bad_binding, "forged_irq")

    def test_unstarted_arm_missed_positive_and_adversarial_protocol(self):
        # Transform only A's final budget dispatch into a failed arm, retaining
        # every real sample/full stop charge and ownership effect. This is a
        # synthetic valid no-entry branch, NOT a claim that native arm None ran.
        data, binding = fixture("budget")
        lines = data.decode().splitlines()
        dispatch = max(i for i, line in enumerate(lines) if line.startswith("TESSRYN_K03_TIMER_DISPATCH ") and " task=0 " in line)
        account = next(i for i in range(dispatch, len(lines)) if lines[i].startswith("TESSRYN_K03_TIMER_ACCOUNT "))
        fields = dict(word.split("=", 1) for word in lines[account].split()[1:])
        grant = dict(word.split("=", 1) for word in lines[dispatch].split()[1:])
        arm_missed = ("TESSRYN_K03_TIMER_ARM_MISSED sequence=0 task=0 generation=" + grant["lease_generation"]
            + " raw=" + fields["capture_raw"] + " now_ns=" + fields["capture_ns"]
            + " soft_ns=" + grant["soft_ns"] + " hard_ns=" + grant["hard_ns"])
        lines[dispatch + 2:account] = [arm_missed]
        # The omitted entry had switched B→A→B; neither switch happened now.
        for i in range(dispatch, len(lines)):
            line = lines[i]
            if line.startswith("TESSRYN_K03_TIMER_ACCOUNT ") and " task=0 " in line:
                line = line.replace("reason=irq outcome=yield", "reason=arm_missed outcome=fail")
                line = re.sub(r"( irqs=| spin_irqs=)([0-9]+)", lambda m: m[1] + str(int(m[2]) - 1), line)
            if line.startswith("TESSRYN_K03_TIMER_MAILBOX ") and " task=0 " in line:
                line = re.sub(r"spin_irqs=([0-9]+)", lambda m: "spin_irqs=" + str(int(m[1]) - 1), line)
            if line.startswith("TESSRYN_K03_TIMER_TERMINAL ") and " task=0 " in line:
                line = line.replace("reason=irq", "reason=arm_missed")
                line = re.sub(r"resumes=([0-9]+)", lambda m: "resumes=" + str(int(m[1]) - 1), line)
            if line.startswith("TESSRYN_K03_TIMER_PASS "):
                line = re.sub(r"(irqs_a=|spin_irqs_a=)([0-9]+)", lambda m: m[1] + str(int(m[2]) - 1), line)
                line = re.sub(r"context_switches=([0-9]+)", lambda m: "context_switches=" + str(int(m[1]) - 2), line)
            lines[i] = line
        unstarted = renumber(("\n".join(lines) + "\n").encode())
        observed = parse_transcript("budget", unstarted, 33, b"", binding)
        self.assertEqual(observed["missed_arms"], 1)
        self.assertEqual(observed["dispatches"], sum(observed["task_resumes"]) + 1)
        for fields in ({"now_ns": 0, "raw": "0x0"}, {"generation": 1}, {"hard_ns": 0}, {"soft_ns": 0}):
            self.bad(change(unstarted, "TESSRYN_K03_TIMER_ARM_MISSED", **fields), binding, "budget")
        # Keep the sample fixed while concealing admission cost or inventing a
        # CPL3 entry: both violate the exact no-entry accounting branch.
        arm_account = sum(line.startswith(b"TESSRYN_K03_TIMER_ACCOUNT ") for line in unstarted.splitlines()[:next(i for i, line in enumerate(unstarted.splitlines()) if b"reason=arm_missed" in line)])
        self.bad(change(unstarted, "TESSRYN_K03_TIMER_ACCOUNT", arm_account, elapsed_ns=0), binding, "budget")
        old_resume = next(line for line in data.splitlines() if line.startswith(b"TESSRYN_K03_TIMER_RESUME "))
        augmented = []
        for line in unstarted.splitlines():
            augmented.append(line)
            if line.startswith(b"TESSRYN_K03_TIMER_ARM_MISSED "):
                augmented.append(old_resume)
        self.bad(renumber(b"\n".join(augmented) + b"\n"), binding, "budget")

    def test_partial_premap_irq_reaches_exact_context_check(self):
        # Valid pre-MAP partial setup is deliberately not required to have the
        # later stable FP hash or sentinel registers yet. It must still carry
        # its precise captured state into the next entry. This prefix mutation
        # intentionally stops at that next-context mismatch, not an FP gate.
        data, binding = fixture()
        lines = data.decode().splitlines()
        arm = dict(word.split("=", 1) for word in next(line for line in lines if line.startswith("TESSRYN_K03_TIMER_ARM ")).split()[1:])
        cancel = next(i for i, line in enumerate(lines) if line.startswith("TESSRYN_K03_TIMER_CANCEL "))
        captured = dict(word.split("=", 1) for word in lines[cancel].split()[1:])
        response = next(i for i in range(cancel, len(lines)) if lines[i].startswith("TESSRYN_K03_TIMER_RESPONSE "))
        irq = ("TESSRYN_K03_TIMER_IRQ sequence=0 task=0 generation=1 capture_raw=" + captured["capture_raw"]
            + " capture_ns=" + captured["capture_ns"] + " target_raw=" + arm["target_raw"]
            + " isr_before=1 isr_after=0 irr_after=0 eoi=96")
        lines[cancel:response + 1] = [irq]
        prefix = renumber(("\n".join(lines) + "\n").encode())
        prefix = pair(prefix, vector=32, rip="0x1000000a0")
        prefix = change(prefix, "TESSRYN_K03_TIMER_TRAP", fp_sha256="1" * 64, r10="0x0", r11="0x0")
        prefix = change(prefix, "TESSRYN_K03_TIMER_ACCOUNT", reason="irq", irqs=1)
        with self.assertRaisesRegex(ValueError, "RESUME field differs"):
            parse_transcript("preemption", prefix, 33, b"", binding)

    def test_replayed_restart_stopped_task_or_extra_records(self):
        data, _ = fixture()
        lines = data.splitlines(keepends=True)
        first_resume = next(line for line in lines if line.startswith(b"TESSRYN_K03_TIMER_RESUME "))
        last_terminal = max(i for i, line in enumerate(lines) if line.startswith(b"TESSRYN_K03_TIMER_TERMINAL "))
        self.bad(renumber(b"".join(lines[:last_terminal + 1] + [first_resume] + lines[last_terminal + 1:])))
        self.bad(renumber(data + next(line for line in lines if line.startswith(b"TESSRYN_K03_TIMER_PASS "))))
        self.bad(change(data, "TESSRYN_K03_TIMER_WAKE", task=0))


if __name__ == "__main__":
    unittest.main()
