/*
	Extends the peer to provide malicious functions that simulate an attacker

	Written by Malo RANZETTI
	January 2023

	                      :::!~!!!!!:.
                  .xUHWH!! !!?M88WHX:.
                .X*#M@$!!  !X!M$$$$$$WWx:.
               :!!!!!!?H! :!$!$$$$$$$$$$8X:
              !!~  ~:~!! :~!$!#$$$$$$$$$$8X:
             :!~::!H!<   ~.U$X!?R$$$$$$$$MM!
             ~!~!!!!~~ .:XW$$$U!!?$$$$$$RMM!
               !:~~~ .:!M"T#$$$$WX??#MRRMMM!
               ~?WuxiW*`   `"#$$$$8!!!!??!!!
             :X- M$$$$       `"T#$T~!8$WUXU~
            :%`  ~#$$$m:        ~!~ ?$$$$$$
          :!`.-   ~T$$$$8xx.  .xWW- ~""##*"
.....   -~~:<` !    ~?T#$$@@W@*?$$      /`
W$@@M!!! .!~~ !!     .:XUW$W!~ `"~:    :
#"~~`.:x%`!!  !H:   !WM$$$$Ti.: .!WUn+!`
:::~:!!`:X~ .: ?H.!u "$$$B$$$!W:U!T$$M~
.~~   :X@!.-~   ?@WTWo("*$$$W$TH$! `
Wi.~!X$?!-~    : ?$$$B$Wu("**$RM!
$R@i.~~ !     :   ~$$$$$B$$en:``
?MXT@Wx.~    :     ~"##*$$$$M~

*/

package impl

import (
	"fmt"
	"math/rand"

	"github.com/rs/xid"
	"go.dedis.ch/cs438/logr"
	"go.dedis.ch/cs438/types"
)

// Overload the certificate catalog by spoofing certificates
// Goal:
// + Prevent anyone from being banned by possibly making it impossible to reach a consensus
// + Overload the certificate catalog
func (n *node) SpoofCertificates(totalGenerated int) error {
	// broadcast a bunch of bogus messages
	for i := 0; i < totalGenerated; i++ {
		// Generate fake name using a random string
		name := randomIP()
		// Who cares, we can even use our own PEM instead of generating a fake one
		pem := n.certificateStore.GetPublicKeyPEM()

		msg := types.CertificateBroadcastMessage{
			Addr: name,
			PEM:  pem,
		}

		// Marshall the CertificateBroadcastMessage
		m, err := n.conf.MessageRegistry.MarshalMessage(&msg)
		if err != nil {
			return err
		}
		err = n.Broadcast(m)
		if err != nil {
			return err
		}
	}
	return nil
}

func randomIP() string {
	return fmt.Sprintf(
		"%d.%d.%d.%d",
		rand.Intn(255),
		rand.Intn(255),
		rand.Intn(255),
		rand.Intn(255),
	)
}

// Attempt to force a ban
// Goal:
// + Ban who we want as a single node
// + Try to overload the trust system
func (n *node) ForceBan(target string) error {
	// Attempt 1: Spam accept messages

	pv := types.PaxosValue{
		UniqID: xid.New().String(),

		Filename: target,
		Metahash: "",
	}

	logr.Logger.Warn().Msgf("Attempting to ban %v", pv)

	n.Ban(target)

	amount := 15
	for i := 0; i < amount; i++ {
		// Generate a fake BanPaxosAcceptMessage
		pf, _ := n.BuildProof(target, "accept")
		msg := types.BanPaxosAcceptMessage{
			Source: n.addr,
			Step:   n.banPaxos.currentStep.Get(),
			ID:     n.banPaxos.currentPaxosInstance.lastUsedPaxosID + uint(i),
			Proof:  pf,
			Value:  pv,
		}

		// Marshall the BanPaxosAcceptMessage
		m, err := n.conf.MessageRegistry.MarshalMessage(&msg)
		if err != nil {
			return err
		}
		err = n.Broadcast(m)
		if err != nil {
			return err
		}
	}

	// Attempt 2: Spam TLC messages

	for i := 0; i < amount; i++ {
		// Generate a fake TLCMessage
		pf, _ := n.BuildProof(target, "tlc")
		val := types.PaxosValue{
			UniqID:   xid.New().String(),
			Filename: target,
			Metahash: "",
		}
		bl := n.banPaxos.createBlockchainBlock(val)
		msg := types.BanTLCMessage{
			Source: n.addr,
			Proof:  pf,
			Block:  *bl,
			Step:   n.banPaxos.currentStep.Get(),
		}
		// Marshall the TLC
		m, err := n.conf.MessageRegistry.MarshalMessage(&msg)
		if err != nil {
			return err
		}
		err = n.Broadcast(m)
		if err != nil {
			return err
		}
	}

	// Attempt 3: Spam TLC messages with a fake source

	for i := 0; i < amount; i++ {
		// Generate a fake TLCMessage
		pf, _ := n.BuildProof(target, "tlc")
		val := types.PaxosValue{
			UniqID:   xid.New().String(),
			Filename: target,
			Metahash: "",
		}
		bl := n.banPaxos.createBlockchainBlock(val)
		//Generate fake IP
		ip := randomIP()
		msg := types.BanTLCMessage{
			Source: ip,
			Proof:  pf,
			Block:  *bl,
			Step:   n.banPaxos.currentStep.Get(),
		}
		// Marshall the TLC
		m, err := n.conf.MessageRegistry.MarshalMessage(&msg)
		if err != nil {
			return err
		}
		err = n.Broadcast(m)
		if err != nil {
			return err
		}
	}
	return nil

}

// Impede onion traffic by blocking tor messages
// Goal:
// + Prevent onion traffic from being sent

func (n *node) ImpedeOnionTraffic() error {
	// Prevent onion traffic from being sent
	n.isMalicious = true
	err := n.RegisterAsOnionNode()
	if err != nil {
		return err
	}

	// Do something
	return nil
}
