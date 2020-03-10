var express = require('express');
var router = express.Router();
var jwt = require("jsonwebtoken");
const uuidv4 = require('uuid/v4');

// database
var Pool = require("ibm_db").Pool;
var ibmdb = new Pool();

var cn = process.env.DB;
var enrollAvaiableBegin = 1553472000000; // 2019-03-25 08:00:00
var enrollAvaiableEnd = 1553677200000; // 2019-03-27 17:00:00
var adminList = ['027267858', 'AVNBTG858', 'ZZ02FV672'];


const qrCodeMap = {"ZZ00LD2170dd76":{"name":"Ada Hsieh"},"086910eeb6db9f":{"name":"Alex LS Chen"},"062724296bae62":{"name":"Albert HT Chen"},"2006553e48e681":{"name":"Ada TC Hsu"},"02302130ae010b":{"name":"Alex SH Lin"},"201394c81bb517":{"name":"Amy CY Chen"},"2012984f567785":{"name":"Adam CJ Tsai"},"027267daacaa60":{"name":"Allen Green Huang"},"0626546794a915":{"name":"Allen PY Huang"},"064249d24b3a48":{"name":"Angella C Chen"},"2003459c1a5e23":{"name":"Allen YF Chen"},"085693adca2c27":{"name":"Albert YC Tsai"},"013638f8da107e":{"name":"Alex Chen"},"0118446152821d":{"name":"Amy CW Chen"},"201299da1ca3d9":{"name":"Alex CJ Liu"},"05422Ac23d428b":{"name":"Alice WJ Chung"},"032374227a004d":{"name":"Allen YL Sheu"},"030540d3880abf":{"name":"Ann Duan"},"01388310c577ab":{"name":"Aron PY Lin"},"02706058513ba3":{"name":"Andrew CM Huang"},"04779360e1b537":{"name":"Ally CP Chen"},"ZZ00L47375287b":{"name":"Andy Shih"},"ZZ00KJ1fc7b1a5":{"name":"Amber Lin"},"0402597e5ba7d1":{"name":"Andrew Hwang"},"2004893273f228":{"name":"Andy CY Lin"},"013639bd2d59bb":{"name":"Angel Chen"},"053766a7994b91":{"name":"Bella YW Yin"},"ZZ00MZ62884c73":{"name":"Ashley Shao"},"ZZ00KNa87c9c84":{"name":"Asia Lin"},"09526752201190":{"name":"Ben CT Wu"},"040622a40dc9db":{"name":"Alpha JF Hsu"},"053767d2bdd8e5":{"name":"Bernie PC Huang"},"2014611a26506c":{"name":"Ben WK Huang"},"0296060bbb893b":{"name":"Angela A Lu"},"ZZ00JYb44efede":{"name":"Boris Chuang"},"ZZ00KD6ce35456":{"name":"Brian Hung"},"043496976e71a3":{"name":"Andy HI Wang"},"0512843483de04":{"name":"Ann Lin"},"026935ef41ba00":{"name":"Ashley TY Guo"},"ZZ00JNfa2be86e":{"name":"Bob Ke"},"02694725971666":{"name":"Benny CH Chuo"},"ZZ00NGba32fb61":{"name":"Bruce Lee"},"ZZ00KZ9bf9361e":{"name":"Candice Tsai"},"051555798eceaa":{"name":"Ann YC Lin"},"ZZ00NH946529ad":{"name":"Brian Tsai"},"0061428024dfe9":{"name":"Casper Su"},"ZZ00L519b8f749":{"name":"Caitlin Chang"},"026889536cdbf6":{"name":"Candy Li"},"0138841693fb9d":{"name":"Cassie WC Lee"},"2004701da35e71":{"name":"Cara WJ Lee"},"0344524746e83f":{"name":"Ardy T Miao"},"0384474cbe5fd5":{"name":"Celia CH Wu"},"08708202baca7f":{"name":"Cathy C Liu"},"ZZ00NUd657c641":{"name":"Cathy Lin"},"ZZ00LH9308afee":{"name":"Charlie Chen"},"ZZ00LUd7a2cb75":{"name":"Charlene Wang"},"201447b86d10bd":{"name":"Charles CL Wu"},"ZZ00JU164b21db":{"name":"Charlotte Chen"},"01353819e38817":{"name":"Chiu-Min CM Chuang"},"ZZ00KQ5cf4e10b":{"name":"Chris Yu"},"ZZ00ME1f6746c1":{"name":"Chris Yang"},"ZZ00MBe8f56f3b":{"name":"Charlene Chou"},"ZZ00NQ51c3756a":{"name":"Chen Yu Chen"},"0268910f2fcc0e":{"name":"Daniel CF Chang"},"0515897c2c6765":{"name":"Daniel LY Lin"},"051740d57b224e":{"name":"Chevy HC Lin"},"2003035b0f4060":{"name":"Clyde CM Lin"},"052918a8d25829":{"name":"Deacon Lin"},"ZZ00JO672fdfc0":{"name":"Colin Tai"},"061051decb0d14":{"name":"Christine ST Lin"},"ZZ00OF4147b492":{"name":"Claire Peng"},"051445f58f7ba9":{"name":"Dennis HJ Lin"},"201360136a3dd5":{"name":"Connie Hung"},"052991eff27309":{"name":"Clark YC Chen"},"ZZ00LXb917783f":{"name":"Coco Lo"},"040260814ca92b":{"name":"Doris Hsiung"},"067274116e0df2":{"name":"Arthur CS Yu"},"020076ed22ca90":{"name":"Elissa Wun"},"013292acf392b4":{"name":"CW Chiang"},"2004132b531ffc":{"name":"Dahlia TL Feng"},"200923b4f81487":{"name":"Danny SC Lee"},"05422C940cc507":{"name":"Ellen YH Sun"},"02572610a5a305":{"name":"Eric Tsao"},"ZZ00NN1f47c0d5":{"name":"Evan Liu"},"0553163b0a8ee8":{"name":"Bernie WT Chen"},"ZZ00L9ab975b3d":{"name":"Dave Hsueh"},"ZZ00KW897fcc6b":{"name":"Evie Cheng"},"013846c58f5480":{"name":"Cynthia YJ Lin"},"013395e3153eba":{"name":"Daniel SC Chou"},"057358522fa04d":{"name":"David MW Hu"},"0343966fbe4669":{"name":"Faco HY Fang"},"ZZ00N346de519f":{"name":"Edward Chang"},"ZZ00JB0ab2a3f9":{"name":"Bill Shih"},"02699738783c7c":{"name":"Bill Wang"},"048403ef930404":{"name":"Emily PC Hsu"},"078868a79da2ee":{"name":"Dennis WK Huang"},"2007539a79ff2f":{"name":"Eric WC Lee"},"040971532c9671":{"name":"Bin SP Ho"},"ZZ00LTc1726fe2":{"name":"Duke Wu"},"052902415b3ce1":{"name":"Felix Lin"},"ZZ00KR8fe1fa4e":{"name":"Eunice Lin"},"ZZ00IIbdae37c4":{"name":"Eva YF Tsai"},"ZZ00KBe28a2a39":{"name":"Eason Liu"},"20049033df3106":{"name":"Fion HP Lee"},"ZZ00JJ99647fd8":{"name":"Fish Huang"},"026998b0ee2c93":{"name":"Evie CI Su"},"002709b0b737c6":{"name":"Frank MH Lee"},"ZZ00M212c85f5f":{"name":"Flora Chao"},"013513896f1967":{"name":"Grace CT Chien"},"200304c80c624e":{"name":"CH Liu"},"04106597a0c070":{"name":"Fred CC Huang"},"ZZ00O761ce1625":{"name":"Charles Jian"},"0337292755c21a":{"name":"Gary TJ Ke"},"ZZ00JV62354271":{"name":"Edward Tien"},"05272Ad1fcb28e":{"name":"Effie Lin"},"0966374bf445ea":{"name":"Elaine WT Wan"},"041113ed5fdc08":{"name":"Hank Chiu"},"20092585d03ce9":{"name":"Charlotte AC Liu"},"0230221d452d8b":{"name":"Gavin JH Wu"},"0410385836b9a6":{"name":"Hawk CH Hu"},"04111B0bccf613":{"name":"Hitomi Deng"},"056393361c0853":{"name":"George G Wang"},"028039b98fd131":{"name":"Huant HT Chou"},"ZZ00IK9b4b6fd9":{"name":"Cheni Yen"},"2005583acd5ed4":{"name":"Elisa KJ Lin"},"0510919ee85e66":{"name":"Chi Wen Lee"},"0326186f060050":{"name":"Ian PY Chen"},"2012572ca2845b":{"name":"Gino KC Chiu"},"ZZ00MUb9205776":{"name":"Emily Lee"},"0155018467fde2":{"name":"Irene MF Tsai"},"ZZ00NK8119dca3":{"name":"Eric Yang"},"ZZ00KO5388639b":{"name":"Chiao Wang"},"040552db81e8e5":{"name":"Glaser Wong"},"085954a5b55c68":{"name":"Christine YT Huang"},"03235700fe6bea":{"name":"Hank HC Liu"},"0363430963ccf3":{"name":"Hank YJ Chiang"},"084319c847b468":{"name":"Cyndi HY Huang"},"01369547fb3580":{"name":"Eva YF Chen"},"05821905497aff":{"name":"Isaac Yeh"},"ZZ00MT71dcec8e":{"name":"Finn Hung"},"ZZ00KG88adf61a":{"name":"Harry Lai"},"09665738606721":{"name":"Daisy CC Wu"},"0445342ed7e0da":{"name":"Heng Yi Chiang"},"201472ab472389":{"name":"Henry CY Hsu"},"057972ed67b8bc":{"name":"Honsam HS Mak"},"026934fcbd0f02":{"name":"Issac JH Weng"},"ZZ00LNb918d7c1":{"name":"Howard Chang"},"035002af140cba":{"name":"Gesse YT Wang"},"02172741acfd45":{"name":"Daisy SH Chuang"},"06837959e8ca99":{"name":"Elton YC Hung"},"0138829ce250ae":{"name":"Eric PC Chen"},"030555e9f6fc78":{"name":"Howel Fan"},"030702911d45b5":{"name":"Eveline CH Lu"},"201053d9acbbf0":{"name":"George CC Tsang"},"05157984772c7b":{"name":"Han Lin"},"200215aebda579":{"name":"Huber PM Liu"},"0410448b51d65b":{"name":"Hanson HW Hung"},"056835d66c4e41":{"name":"Hank CH Chan"},"072576bbfe80b5":{"name":"Ivan Peng"},"01352330d52575":{"name":"Hank Chen"},"200266b6e6f97a":{"name":"Jack CP Lee"},"04994522750e78":{"name":"Herman JH Li"},"041899f47c0145":{"name":"Iven CH Liu"},"201089e39d2367":{"name":"Horance CH Chou"},"0325826e174418":{"name":"Ian HY Sun"},"ZZ00LVdf079cc3":{"name":"Irene Kuo"},"ZZ00KT1ea420eb":{"name":"Ivy Lin"},"20036834b865e2":{"name":"Jack CC Hsiao"},"09884281f14105":{"name":"Jacky JH Yeh"},"ZZ00J412401eb0":{"name":"Harry Lin"},"ZZ00NVc78fa31c":{"name":"Jamie Yang"},"0445209ecab78c":{"name":"Jack Chiang"},"ZZ00N513f7f2d3":{"name":"Howard Ko"},"0218975c66cc68":{"name":"Hsiang Chih"},"085685051217b2":{"name":"Irene PW Tien"},"05178580a8cc10":{"name":"Jamie CY Lin"},"0657732574bac3":{"name":"Irene Y Huang"},"05422B86119d99":{"name":"Jason HT Chen"},"01353615fbe248":{"name":"Jeff CC Chao"},"ZZ00N6c961bfce":{"name":"Jerry CP Huang"},"ZZ00MRdd54d0ed":{"name":"Jacky Wu"},"ZZ00MF6fbd2a70":{"name":"Jane Liu"},"055061ba118f59":{"name":"James J Lu"},"048187ff2d10a1":{"name":"Iris YH Kao"},"026986180e0d3f":{"name":"Jack SJ Yang"},"20092414824cf9":{"name":"Jimmy CM Huang"},"02794720322401":{"name":"Jocelyn Yang"},"013217d16a65f4":{"name":"Jason Chang"},"ZZ00M7e521a66b":{"name":"Javio Su"},"ZZ00LFef025456":{"name":"Jacky Chu"},"02692689f2c944":{"name":"Jay CC Tsao"},"051722b5a31805":{"name":"Janus SC Liang"},"ZZ00K0e985a65c":{"name":"Jay Hsiao"},"00031527754909":{"name":"Jeff CH Tsang"},"0141916acc2d89":{"name":"Jason CY Chen"},"051720b141dcc3":{"name":"Jeff JF Liu"},"ZZ00JA53443d29":{"name":"Jeremy Huang"},"ZZ00LMb1544bcb":{"name":"Jason Lee"},"ZZ00IG49c38542":{"name":"Jean Lee"},"ZZ00LZ0b995990":{"name":"Jerry Chen"},"0356246c512ab0":{"name":"Johnson J Chao"},"ZZ00J5ce90b354":{"name":"Joseph Wang"},"048186b7ec60c5":{"name":"Jesse Ko"},"ZZ00LA9b1b49cb":{"name":"Jill Hsu"},"ZZ00OBfd0f239b":{"name":"Jim Wu"},"20124577f6880b":{"name":"Jesse Wei"},"ZZ00MWebd24b7a":{"name":"Joan Tsai"},"ZZ00NM5ab632d2":{"name":"Joy Lin"},"ZZ00MY9f7a058b":{"name":"Jeff Ke"},"056351f0eaac57":{"name":"Jeff SW Hsu"},"ZZ00JK07e37dfd":{"name":"Joyce Lin"},"037356e3d40865":{"name":"Judy YJ Li"},"ZZ00LL4bf50673":{"name":"Jessie Yu"},"200452b4847820":{"name":"Jimmy Chen"},"050881ba3c8e71":{"name":"Julia CJ Lin"},"ZZ00KI32250af5":{"name":"Jimmy Ku"},"02803893fe91ba":{"name":"John YP Chang"},"053768b831481a":{"name":"Jennifer SM Chen"},"ZZ00O837098bde":{"name":"Jimmy CY Huang"},"201463d72473a7":{"name":"JM CM Wang"},"026888e4ed1073":{"name":"Joe MF Fan"},"2013997c3db905":{"name":"John CH Tang"},"ZZ00L3cbd945fb":{"name":"Joelle Lin"},"0136835f5bed63":{"name":"Johnny KT Chang"},"01298B6b2e3593":{"name":"Joyce Chang"},"048196e23012da":{"name":"Johnny YM Kao"},"02698706d7cdfd":{"name":"Julie YJ Chen"},"0512926e64e285":{"name":"Angela YC Li"},"026990628878af":{"name":"Juicy YH Lee"},"030560e9c1b629":{"name":"Johnson Feng"},"085676fecbd1fa":{"name":"Karen KK Ting"},"ZZ00MV0855e19a":{"name":"Kai Chang"},"2004614696b58b":{"name":"Karen KY Huang"},"201010606d8198":{"name":"Kate TY Liao"},"013150eac605ca":{"name":"Kathleen Chao"},"03241520cd5ac4":{"name":"Kathy CH Wu"},"2013423b4b98ae":{"name":"Johnson Wang"},"ZZ00L010d8de82":{"name":"Joy Lee"},"ZZ00IV409f59c2":{"name":"Jun Bin JB Zuan"},"057503c1fefae3":{"name":"Katy HM Lin"},"2014649fb5b981":{"name":"Kathy SY Chen"},"20040271fc8d9f":{"name":"Katy KD Yeh"},"ZZ00LC7de8581e":{"name":"Kelly Lee"},"05749934789bda":{"name":"Kella YT Lin"},"ZZ00LRaabaa784":{"name":"Kent Yang"},"023020f26290d9":{"name":"Kris Huang"},"05158A7a7fe774":{"name":"Kelly KL Wang"},"013559b3c079c3":{"name":"Kelvin SH Chen"},"0409772c540bfa":{"name":"Kevin TY Hsu"},"ZZ00L1c711e5cc":{"name":"Kimber Chen"},"ZZ00JIfe6678eb":{"name":"Ken Cheng"},"ZZ00MN12067816":{"name":"Lawrence Lan"},"04168886cfba75":{"name":"Leo CW Liu"},"026890782dfade":{"name":"Kirby Ko"},"ZZ00K583403856":{"name":"Kevin CH Lee"},"055928f370cc7c":{"name":"Kenny CC Tseng"},"051746a8761f99":{"name":"Kevin CL Lin"},"ZZ00LEbf6d8aec":{"name":"Kevin Wu"},"013454350b0620":{"name":"KT Chen"},"030549e066e24d":{"name":"Leo Y Fan"},"ZZ00IH65354013":{"name":"Kevin Chai"},"05145656685f8f":{"name":"Leo JM Huang"},"ZZ00MQ6d3ae0d5":{"name":"Leon Hsu"},"ZZ00L89bf6c050":{"name":"Leon KH Chen"},"200606044d6090":{"name":"Lily LC Chen"},"048184ee7f38d3":{"name":"Lenny LY Kuo"},"026991826bd80c":{"name":"Liyard TY Yang"},"ZZ00MGf03d3739":{"name":"Lorwi CH Chen"},"0542289b941f85":{"name":"Lucy CH Yang"},"ZZ00NS0bd68078":{"name":"Maggie Yao"},"099115901f8b4f":{"name":"Marc CF Tseng"},"200538c5663576":{"name":"Mark SJ Chang"},"2013337719ab06":{"name":"Maggie W Chen"},"ZZ00JF9c5fdce7":{"name":"Kevin Lee"},"095292764b5ae7":{"name":"Matt Wen"},"ZZ00LI55e9a47a":{"name":"Kevin Wang"},"ZZ00K38e8523eb":{"name":"Kiwi Liu"},"2005142b8bde63":{"name":"Lilian MY Hung"},"0603955703322f":{"name":"Mi Mi Sun"},"052593b9d24ac2":{"name":"Max HH Liu"},"ZZ00L77d9aecbe":{"name":"Lin Ga Tsan"},"ZZ00LYe7ce66df":{"name":"Michael Liu"},"ZZ00MLb13fe852":{"name":"Mellow Fang"},"051270ef2bc49d":{"name":"Mingling Lee"},"010778974b2c15":{"name":"Mei W Hong"},"2002469eed4b61":{"name":"Melody AN Chen"},"048143765e01c0":{"name":"Michael TL Kuo"},"05526030ff1a22":{"name":"Lily LC Hsu"},"068368b2c24ef8":{"name":"Lily WJ Yu"},"013338e8998185":{"name":"Mike WF Chang"},"05486256178554":{"name":"Lina Chuang"},"0049644610d11b":{"name":"Michelle LT Ho"},"20022094121e1a":{"name":"MJ H Hsieh"},"026999db85ebc5":{"name":"Oliver HY Kuo"},"041574dd51f452":{"name":"Lucy WC Lin"},"ZZ00J8c1c00081":{"name":"Maido Hsieh"},"01377282d243c1":{"name":"Monica Chang"},"ZZ00MA48a6a0f2":{"name":"Peggy Li"},"05743740f7da3b":{"name":"Nadia C Hsu"},"08261652f5622e":{"name":"Patrick LC Wei"},"ZZ00KL931c9b15":{"name":"Rebecca Chu"},"0529645c0dd1dd":{"name":"Peggy PC Liu"},"0481605c11a192":{"name":"Remond CK Ku"},"026945da5af7bc":{"name":"Morgan TF Chen"},"028621ac8d161c":{"name":"Richard BC Kang"},"035004bb739745":{"name":"Nick HH Yin"},"06800432fd117d":{"name":"Nick MH Tsai"},"0273270b85f76e":{"name":"Sam Ko"},"0323371db4b94b":{"name":"Mars KT Yang"},"201003c00bbec8":{"name":"Oliver HC Wang"},"ZZ00NF38f712dc":{"name":"Mick He"},"04814896ab94a9":{"name":"Patrick Kuo"},"ZZ00NR9d1f6a00":{"name":"Peter Wei"},"ZZ00IQ522046b4":{"name":"Po Wei Chang"},"032338ce41d068":{"name":"Natalie PW Huang"},"ZZ00KUd66cf829":{"name":"Shawn Ke"},"ZZ00M802ccf83b":{"name":"Randy Ho"},"010175692d66f3":{"name":"Rick Hsieh"},"0556898ad6be02":{"name":"Sherry SY Lee"},"081557e53a08e1":{"name":"Robert PH Su"},"02699605cbb1e6":{"name":"Ronald W Wang"},"040989fd3d686b":{"name":"Sam CH Hsueh"},"0578053ba8a58a":{"name":"Shih Ting ST Huang"},"200174009d1e54":{"name":"Polo Lu"},"201156006a261f":{"name":"Noel CL Chen"},"093555c5895b6b":{"name":"R.J. Wang"},"ZZ00LSd71b4f5b":{"name":"Sam Chung"},"008267d813df69":{"name":"Rachel HC Yen"},"ZZ00KY8bc70317":{"name":"Pamela Shie"},"ZZ00ILfaf09999":{"name":"Pei Ju Chen"},"ZZ00OH80f40eae":{"name":"Penny Wang"},"ZZ00KF97ba0e41":{"name":"Sarah Gau"},"ZZ00LQ399ab6b8":{"name":"Shao Lu"},"ZZ00M56910b722":{"name":"Pochien Hao"},"0953267918c939":{"name":"Randy TY Wang"},"ZZ00MH5fa7318f":{"name":"Sharlin PC Lai"},"0192031b9e99e0":{"name":"Queena Tsai"},"026650a3b9cb4f":{"name":"Richard CC Lee"},"ZZ00M3e165cb0a":{"name":"Sharon Chen"},"ZZ00NC6d7b5abc":{"name":"Rey Han Shan"},"027256decd072a":{"name":"Shawn L Lin"},"201122dc269cd6":{"name":"Sherry HH Huang"},"0405393508ab94":{"name":"Ricky SH Ho"},"051614feb12dea":{"name":"Sidney Lee"},"ZZ00M4b274f27b":{"name":"Simon HO Huang"},"05160434770c01":{"name":"Steve SK Lu"},"0490301e8b72bb":{"name":"Robin Wu"},"ZZ00NB486af8a8":{"name":"Sun Yu"},"201258f1b79154":{"name":"Tim TY Liao"},"ZZ00JP76b17de7":{"name":"Shirley Lin"},"ZZ00J9bbed51ad":{"name":"Richi Chen"},"0503455c8c55c0":{"name":"Tim YC Yen"},"051623b24134b6":{"name":"Roxana HH Lee"},"0877982faec15e":{"name":"Roren LP Yen"},"0269882f19a4fb":{"name":"Sean CY Chen"},"026948167fa935":{"name":"Shawn CH Liu"},"05299040360acf":{"name":"Tom JT Lo"},"0518241e2b62d5":{"name":"Tommy TC Lu"},"013651febddaed":{"name":"San C Chen"},"ZZ00OG84280abf":{"name":"Sheila Li"},"ZZ00IW2ddf2b3a":{"name":"Shu Chi Lin"},"ZZ00MI89eb8da1":{"name":"Shu Chi Pai"},"2011499a05e220":{"name":"Victor JF Hsu"},"026899cdb3c6dd":{"name":"Sandy HC Lin"},"ZZ00K492c178bf":{"name":"Scott Chen"},"0815686018205d":{"name":"Sky KY Shao"},"ZZ00K935eaa45c":{"name":"Scott Liao"},"051318aa9a0f8b":{"name":"Song-Hsi Lin"},"ZZ00M9dccdaa5c":{"name":"Shawn Jou"},"200657cfc6cac8":{"name":"Shiang CS Chen"},"ZZ00MJ061bc766":{"name":"Shu Yu"},"201419fcafbf23":{"name":"Vincent CY Chan"},"ZZ00KX107c686f":{"name":"Spin Huang"},"ZZ00KC8f17d23a":{"name":"Simon Lee"},"0987811de49ecc":{"name":"Vincent YC Yeh"},"0528322e8bd574":{"name":"Silvia Lin"},"ZZ00IF28feb565":{"name":"Viola Lin"},"006028c182e31d":{"name":"Stanley Chou"},"ZZ00M128df4ee8":{"name":"Steven Meng"},"098720d0e6870a":{"name":"Sonia ML Yang"},"ZZ00IS152086fd":{"name":"Ting Yueh Shih"},"04772895777281":{"name":"Tom PH Chu"},"2014241b87aa8b":{"name":"Sophie SF Tsou"},"01732210864035":{"name":"Steven Wang"},"ZZ00LBd30ad304":{"name":"Tommy Shih"},"ZZ00IB05bdceee":{"name":"Walson Yeh"},"20066244125377":{"name":"Tracy YW Chang"},"200459e9f6ceb4":{"name":"Hong JH Wu"},"026992ca837b08":{"name":"Tabitha Chan"},"201069e3f48490":{"name":"Wayne C Chang"},"026946512ac07e":{"name":"Vera C Chen"},"053330ad6f3cb1":{"name":"Tammy H Chang"},"ZZ00LW29302500":{"name":"Sophia Yang"},"084337799dbbd7":{"name":"Teresa CC He"},"ZZ00O173c96103":{"name":"Vic Wang"},"09876120fa437d":{"name":"Sunny SY Yang"},"022314c281ab50":{"name":"Tu JK Kenneth"},"ZZ00O127fbc1df":{"name":"Vic Wang"},"201370042d02d0":{"name":"Victor Hung"},"ZZ00NDa49d30e5":{"name":"Teresa Yu"},"0405292fad2587":{"name":"Vincent Hsu"},"02694927532321":{"name":"Wayne ST Lai"},"ZZ00J6d96cdbaf":{"name":"Wells Wang"},"083332baece5e4":{"name":"Wendy WH Tseng"},"024402564c7b3f":{"name":"Tony LF Yang"},"027000e6fbf522":{"name":"Winni Wang"},"09452778d680a4":{"name":"Tony Wang"},"ZZ00NI3452b305":{"name":"Vincent HY Hu"},"ZZ00JEb9fe449f":{"name":"Wester Wei"},"002150aad73398":{"name":"Usher Huang"},"201139f49530f0":{"name":"Vincent Tsai"},"0680797c195567":{"name":"Valen YC Chang"},"07826083da7570":{"name":"Will HY Tseng"},"ZZ00K853d4e069":{"name":"William Li"},"200365a5b7e1fc":{"name":"Vincent CL Chen"},"ZZ00LK0bca597b":{"name":"Winnie Kuo"},"013206ab0a54c5":{"name":"Win-Lin Chou"},"0952960796f170":{"name":"Wayen WJ Wu"},"200171b074cf9a":{"name":"Wayne Yu"},"ZZ00N459e84a08":{"name":"Vivian Chang"},"ZZ00NO76840907":{"name":"Ya Hsuan Lin"},"0513418350bc1d":{"name":"Winnie Liu"},"ZZ00JZc117b97d":{"name":"Winnie WY Chen"},"0463221c155de1":{"name":"Winnie WY Lo"},"ZZ00L2a656476e":{"name":"Yaoyu Tsai"},"ZZ00J2e89b5a41":{"name":"Yu Hsuan Lin"},"053228dc8e1749":{"name":"Yuz TY Tsai"},"053042a3905c23":{"name":"Zhi Hua Chien"},"ZZ00K276dc487e":{"name":"Yuhsing Chang"},"040527d1bcba85":{"name":"Wayne Hsu"},"040999b161b5c3":{"name":"Jenny HC Huang"},"20078485b24e2e":{"name":"Jessie YG Wang"},"0136418d878376":{"name":"Szu-Jui Chen"},"0411317d82f77f":{"name":"Tiffany SJ Hsu"},"ZZ00M075e15d2f":{"name":"Winston Chen"},"ZZ00J392e8a022":{"name":"Yi An Chen"},"ZZ00IZafcff8f3":{"name":"Yao Han Chang"},"ZZ00ITb4b03ee7":{"name":"Yi Huan Chen"},"ZZ00IU323e7018":{"name":"Yi Ting Hsin"},"056939f8c3bcbb":{"name":"Yvonne YF Tsai"},"05401345767401":{"name":"Zoe CI Lin"},"026776d21be3ce":{"name":"Zoe HF Yen"},"018104136a3eae":{"name":"Irene TH Hsieh"},"ZZ00OK9692c5cc":{"name":"Susan Huang"},"ZZ00O968394d55":{"name":"Josh Hu"},"ZZ00OJfaaf1614":{"name":"Carol Huang"},"ZZ00KPeea51bfe":{"name":"Gary Chang"},"018428ec32a61b":{"name":"Jessica Ho"}};

var currentTs = function() {
	// generate timestamp
	var now = new Date;
	var utc_timestamp = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(),
		now.getUTCHours(), now.getUTCMinutes(), now.getUTCSeconds(), now.getUTCMilliseconds()) + 8 * 60 * 60 * 1000;
	var twTimestamp = new Date(utc_timestamp).toJSON().replace(/T/i, ' ').replace(/Z/i, '');
	return twTimestamp;
};

var customlogger = {
	info: function(sessionId, sessionSn, loginfo) {
		var finalPrintContent = '';
		for (var i = 0; i < loginfo.length; i++) {
			var printInfo = loginfo[i];
			if (typeof loginfo[i] === 'object') {
				printInfo = JSON.stringify(loginfo[i]);
			}
			finalPrintContent += printInfo;
			finalPrintContent += " ";
		}
		var now = currentTs();
		console.log('[' + now + '|' + sessionId + '|' + sessionSn + '] ' + finalPrintContent);
	}
};

function camelize(str) {
	var rtl = "";
	var arr = str.split("_");
	for (var i = 0; i < arr.length; i++) {
		rtl += arr[i].replace(/(?:^\w|[A-Z]|\b\w|\s+)/g, function(match, index) {
			if (+match === 0) return ""; // or if (/\s+/.test(match)) for white spaces
			return index == 0 ? match.toUpperCase() : match.toLowerCase();
		});
	}
	rtl = rtl.charAt(0).toLowerCase() + rtl.slice(1);
	return rtl;
}

function convertKeysToCamelize(obj) {

	// array
	if (Array.isArray(obj)) {
		for (var i = 0; i < obj.length; i++) {
			for (var propertyName in obj[i]) {
				var old_key = propertyName;
				var new_key = camelize(old_key);
				if (old_key !== new_key) {
					Object.defineProperty(obj[i], new_key,
						Object.getOwnPropertyDescriptor(obj[i], old_key));
					delete obj[i][old_key];
				}
			}
		}
		return obj;
	}

	return obj;

}

var securityValid = function(inputString) {
	var lt = /</g,
		gt = />/g,
		ap = /'/g,
		ic = /"/g;
	lq = /{/g;
	rq = /}/g;
	inputString = inputString.toString().replace(lt, "&lt;").replace(gt, "&gt;").replace(ap, "&#39;").replace(ic, "&#34;").replace(lq, "").replace(rq, "");
	return inputString;
};

function securityValidObject(obj) {
	if (obj) {
		for (var propertyName in obj) {
			if (typeof obj[propertyName] === 'string') {
				obj[propertyName] = securityValid(obj[propertyName]);
			}
		}
	}
}

module.exports = function(app) {

	/////////////////////////////////////////////////////////////////////////////
	// Core - authenticate
	/////////////////////////////////////////////////////////////////////////////

	// validate JWT on all API calls
	router.use("/", function(req, res, next) {

		// issue a request id
		req.rid = uuidv4();

		// clean request
		securityValidObject(req.body);
		securityValidObject(req.query);

		var sessionId = req.sessionID || req.rid;
		// pring request
		customlogger.info(sessionId, "", ["L001", "request URL:", req.url]);
		customlogger.info(sessionId, "", ["L002", "request JSON:", JSON.stringify(req.body)]);
		customlogger.info(sessionId, "", ["L003", "request QueryString:", JSON.stringify(req.query)]);

		next();
	});

	router.get("/c",
		function(req, res) {

			// clean request
			securityValidObject(req.query);

			try {

				if(!req.query.u) {
					var responseJSON = {
						code: "9901",
						message: "input paramater error"
					};
					customlogger.info(req.rid, "", ["response JSON:", JSON.stringify(responseJSON)]);
					res.status(400).json(responseJSON);
					return;
				}

				var empNum = req.query.u;

				if(qrCodeMap[empNum]) {

					var empNumShort = empNum.substr(0, 6);

					var responseJSON = {
						code: "0000",
						message: "success",
						enrollList: enrollMap[empNumShort],
						notesId: qrCodeMap[empNum].name,
						empNum: empNumShort
					};
					customlogger.info(req.rid, "", ["response JSON:", JSON.stringify(responseJSON)]);
					res.status(200).json(responseJSON);
				} else {
					var responseJSON = {
						code: "2001",
						message: "user not found"
					};
					customlogger.info(req.rid, "", ["response JSON:", JSON.stringify(responseJSON)]);
					res.status(400).json(responseJSON);
				}


			} catch (mainException) {
				customlogger.info(req.rid, "", ["error=", JSON.stringify(mainException)]);
				var responseJSON = {
					code: "9900",
					message: "system error"
				};
				customlogger.info(req.rid, "", ["response JSON:", JSON.stringify(responseJSON)]);
				res.status(400).json(responseJSON);
				return;
			}
		}
	);

	router.get("/c_db",
		function(req, res) {
			try {

				if(!req.query.u) {
					var responseJSON = {
						code: "9901",
						message: "input paramater error"
					};
					customlogger.info(req.rid, "", ["response JSON:", JSON.stringify(responseJSON)]);
					res.status(400).json(responseJSON);
					return;
				}

				var empNum = req.query.u;

				ibmdb.open(cn, function(err, conn) {
					if (err) {
						customlogger.info(req.rid, empNum, ["error=", JSON.stringify(err)]);
						conn.closeSync();
						var responseJSON = {
							code: "9900",
							message: "system error"
						};
						customlogger.info(req.rid, empNum, ["response JSON:", JSON.stringify(responseJSON)]);
						res.status(400).json(responseJSON);
						return;
					}
					// business logic begin
					try {
						//blocks until the query is completed and all data has been acquired
						var rows = conn.querySync("select i.* from enroll e, user_secret s, course_info i where e.course_id = i.course_id and e.emp_num=s.emp_num and s.emp_secret=? order by course_begin asc", [empNum]);
						if (rows.error) {
							throw "SQL Error";
						}
						convertKeysToCamelize(rows);

						for(var i=0; i<rows.length; i++) {
							var arr = Object.keys(rows[i]);
							for(var j=0; j<arr.length; j++) {
								if(rows[i][arr[j]]) {
									rows[i][arr[j]] = eval('"' + rows[i][arr[j]] + '"');
									console.log(rows[i][arr[j]]);
								}
							}
						}		

						conn.closeSync();
						var responseJSON = {
							code: "0000",
							message: "success",
							enrollList: rows
						};
						customlogger.info(req.rid, "", ["response JSON:", JSON.stringify(responseJSON)]);
						res.status(200).json(responseJSON);
						return;
					} catch (err) {
						customlogger.info(req.rid, "", ["error=", JSON.stringify(err)]);
						conn.closeSync();
						var responseJSON = {
							code: "9900",
							message: "system error"
						};
						customlogger.info(req.rid, "", ["response JSON:", JSON.stringify(responseJSON)]);
						res.status(400).json(responseJSON);
						return;
					}
				});
			} catch (mainException) {
				customlogger.info(req.rid, "", ["error=", JSON.stringify(mainException)]);
				var responseJSON = {
					code: "9900",
					message: "system error"
				};
				customlogger.info(req.rid, "", ["response JSON:", JSON.stringify(responseJSON)]);
				res.status(400).json(responseJSON);
				return;
			}
		}
	);

	return router;
};