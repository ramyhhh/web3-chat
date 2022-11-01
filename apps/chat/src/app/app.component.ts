import { Component, ElementRef, Injectable, Input, ViewChild } from '@angular/core';
import { ECDH, HMAC } from './crypto';




export type Message = {
    _id: string
    status: string
    text: string
    sender: string
}


export type MessageGroup = {
    sender: string
    message: Message
    messages: Message[]
}

function buf2hex(buffer: ArrayBuffer): string { // buffer is an ArrayBuffer
    return [...new Uint8Array(buffer)]
        .map(x => x.toString(16).padStart(2, '0'))
        .join('');
}



function dummy(): Message[] {
    return [
        { _id: '1', sender: 'me', status: '✓', text: "helloooooooo Lorem ipsum dolor sit amet consectetur adipisicing elit. Amet voluptate molestias, mollitia quam minima nihil dolores tempora reiciendis distinctio quasi dolorum doloremque suscipit atque neque sint id modi perferendis officiis?", },
        { _id: '1', sender: 'me', status: '✓', text: "عُرف استخدام الملح قديمًا، حيث كان يُستعمل على مر العصور في الطهي والتجارة باعتباره الصخرة الوحيدة القابلة للأكل بالنسبة للإنسان. ويتم استخدامه الآن على نطاق واسع في جميع المطابخ في العالم، إما باستعماله كبهار أو كحافظ مُميز لبعض الأطعمة مثل اللحوم المقددة والسمك. لقد كان للملح تأثير اقتصادي كبير وأحيانًا كان سببًا في وقوع أزمات اقتصادية في بعض الحضارات. يرتبط ارتباطًا وثيقًا بتاريخ المعاملات الاقتصادية في تاريخ البشرية، هناك بعض الأنشطة التي تأثرت باسمه مثل سالاري بمعنى الأجر، أو أسماء بعض الطُرق قبل التارخ مثل روت دو سل في فرنسا وفيا سالاريا في روما القديمة ومدينة ساليناس دي لينث في إسبانيا، كما اعتبروه رمزًا للخصوبة. hello ويؤثر الملح على مذاق الأطعمة ", },
        { _id: '1', sender: 'rami', status: '✓', text: "woorld", },
        { _id: '1', sender: 'rami', status: '✓', text: "hello yourself .. !! 😎" },
        { _id: '1', sender: 'rami', status: '✓', text: "how are you ?" },
        { _id: '1', sender: 'me', status: '✓', text: "helloooooooo", },
        { _id: '1', sender: 'me', status: '✓', text: "woorld", },
        { _id: '1', sender: 'me', status: '✓', text: "woorld", },
    ]
}

@Component({
    selector: 'web3-chat-root',
    templateUrl: './app.component.html',
    styleUrls: ['./app.component.scss'],
})
export class AppComponent {

    @ViewChild('chat') chatWindow: ElementRef<HTMLDivElement> | undefined;

    message = ''

    @Input() messages: MessageGroup[] = []

    groups: MessageGroup[] = [];

    ngOnInit() {
        const messages = dummy()
        this.addMessages(messages, true, 50)
    }



    async sendMessage() {

        const remotePartyRatchet = (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: curve }, false, ['deriveBits'])) as CryptoKeyPair;

        const ratchet = new DoubleRatchet()
        await ratchet.init()

        const SK = await ratchet.generateSecret(ratchet.DHs.privateKey, remotePartyRatchet.publicKey)

        await ratchet.init_r(SK, remotePartyRatchet.publicKey)


        const text = this.message
        this.message = ''

        const msg: Message = {
            _id: '1',
            status: 'loading ...',
            text,
            sender: Math.random() > 0.5 ? "me" : "rami"
        }

        //add to UI
        this.addMessages([msg])

        //add to send queue (via service)
    }

    addMessages(messages: Message[], autoScroll?: boolean, scrollTime?: number) {
        const el = this.chatWindow?.nativeElement
        scrollTime ??= 200
        //autoScroll ??= el ? Math.abs(el.scrollHeight - (el.scrollTop + el.clientHeight)) < 20 : true;

        messages.forEach(msg => { this.addMessage(msg) })

        if (autoScroll)
            setTimeout(() => {
                //this.chatWindow!.nativeElement.scrollTop = this.chatWindow!.nativeElement.scrollHeight;
            }, scrollTime)
    }

    addMessage(msg: Message) {
        const prev = this.groups[0]
        if (prev?.sender === msg.sender) {
            prev.messages.push(msg)
        } else {
            this.groups.splice(0, 0, {
                sender: msg.sender ?? 'unkown',
                message: msg,
                messages: []
            })
        }
    }




}

// MESSAGE PIPELINE (SENDING)
// 1. add to UI
// 2. add to send queue (via service)
// 3. encrypt message (to encrypt we need a msg-key <- hash ratchet <- DH ratchet)
// 4. send message and change status to 'sent'


@Injectable({
    providedIn: 'root'
})
export class MessageService {
    sendMessage(msg: Message) {
        //send to server
    }
}





function GENERATE_DH(): Promise<CryptoKeyPair> {
    return ECDH.generate()
}
function DH(dh_pair: CryptoKeyPair, dh_pub: CryptoKey): Promise<CryptoKey> {
    return ECDH.deriveHmacKey(dh_pair.privateKey, dh_pub)
}


function KDF_RK_HE(rk: CryptoKey, dh_out: CryptoKey): [CryptoKey, CryptoKey, CryptoKey] {
    const ck = HMAC.deriveHmacKey(rk, dh_out)
    return [rk, ck, nhk]
}
function KDF_CK(CKs: CryptoKey): [CryptoKey, CryptoKey] {
    throw new Error('Function not implemented.');
}

function HENCRYPT(hk: CryptoKey, plaintext: BufferSource) {

}

export class DoubleRatchet {

    RK!: CryptoKey //root key

    DHRs!: CryptoKeyPair //sending ratchet key
    DHRr!: CryptoKey //receiving ratchet key

    CKs!: CryptoKey //sending chain key
    HKs!: CryptoKey // sending chain header key
    NHKs!: CryptoKey // sending chain next header key

    CKr!: CryptoKey //recieving chain key
    HKr!: CryptoKey //recieving chain header key
    NHKr!: CryptoKey //recieving chain next header key

    Ns = 0 //number of messages sent
    Nr = 0 //number of messages received
    PN = 0

    MKSKIPPED!: {} //message keys of skipped messages



    async init(SK: CryptoKey, bob_dh_public_key: CryptoKey, shared_hka: CryptoKey, shared_nhkb: CryptoKey) {

        //set ratchet keys
        this.DHRs = await GENERATE_DH()
        this.DHRr = bob_dh_public_key

        const [RK, CKs, NHKs] = KDF_RK_HE(SK, await DH(this.DHRs, this.DHRr))
        this.RK = RK
        this.CKs = CKs
        this.NHKs = NHKs

        this.Ns = 0
        this.Nr = 0
        this.PN = 0
        this.MKSKIPPED = {}

        //this.CKr = null

        this.HKs = shared_hka
        //this.HKr = null
        this.NHKr = shared_nhkb
    }

    RatchetEncryptHE(plaintext:BufferSource, AD) {

        const [CKs, mk] = KDF_CK(this.CKs)
        this.CKs = CKs
        const header = HEADER(this.DHRs, this.PN, this.Ns)
        const enc_header = HENCRYPT(this.HKs, header)
        this.Ns += 1
        return [enc_header, ENCRYPT(mk, plaintext, CONCAT(AD, enc_header))]
    }




}





