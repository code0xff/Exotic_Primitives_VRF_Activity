use rand::{distributions::Alphanumeric, Rng};
use schnorrkel::{
    signing_context,
    vrf::{VRFInOut, VRFPreOut, VRFProof},
    Keypair,
};

fn main() {
    let mut players = Vec::<Player>::new();
    for _ in 0..4 {
        players.push(Player::new());
    }

    let commitals = players
        .iter_mut()
        .map(Player::commit)
        .collect::<Vec<[u8; 16]>>();

    let mut seed = 0;
    for (idx, player) in players.iter().enumerate() {
        let (random_number, random_string) = player.reveal();
        let random_number = random_number.unwrap();
        let random_string = random_string.unwrap();

        let hash = hash_blake2(random_number, random_string);
        if commitals[idx] != hash {
            panic!("cheated player!!!");
        }

        seed += random_number;
    }

    for _ in 0..5 {
        for player in players.iter_mut() {
            player.draw(seed);
            seed += 1;
        }
    }

    let mut winner_value = 0u8;
    let mut winner = 0;
    let context = signing_context("".as_bytes());
    for (player_idx, player) in players.iter().enumerate() {
        let (max_value, (vrf_in_out, vrf_proof)) = player.show_highest_card();
        let idx = player.index.unwrap();
        let res = player.keypair.public.vrf_verify(
            context.bytes(&idx.to_le_bytes()),
            &VRFPreOut::from_bytes(&vrf_in_out.output.to_bytes()).unwrap(),
            &vrf_proof,
        );
        if res.is_ok() && winner_value < max_value {
            winner_value = max_value;
            winner = player_idx;
        }
    }

    println!("Winner Player: {winner}");
}

fn hash_blake2(random_number: u32, random_string: String) -> [u8; 16] {
    sp_core::blake2_128(&format!("{random_number}{random_string}").into_bytes())
}

struct Player {
    keypair: Keypair,
    random_number: Option<u32>,
    random_string: Option<String>,
    max_value: Option<u8>,
    index: Option<u32>,
    proof: Option<(VRFInOut, VRFProof)>,
}

impl Player {
    fn new() -> Self {
        Self {
            keypair: Keypair::generate(),
            random_number: None,
            random_string: None,
            max_value: None,
            index: None,
            proof: None,
        }
    }

    fn commit(&mut self) -> [u8; 16] {
        let random_number = rand::thread_rng().gen_range(0..52u32);
        let random_string: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();

        let hash = hash_blake2(random_number, random_string.clone());
        self.random_number = Some(random_number);
        self.random_string = Some(random_string);
        hash
    }

    fn reveal(&self) -> (Option<u32>, Option<String>) {
        (self.random_number, self.random_string.clone())
    }

    fn draw(&mut self, idx: u32) {
        let context = signing_context("".as_bytes());
        let (vrf_in_out, vrf_proof, _) = self.keypair.vrf_sign(context.bytes(&idx.to_le_bytes()));
        let card = vrf_in_out.as_output_bytes()[0] % 52;
        if let Some(max_value) = self.max_value {
            if max_value < card {
                self.max_value = Some(card);
                self.proof = Some((vrf_in_out, vrf_proof));
                self.index = Some(idx);
            }
        } else {
            self.max_value = Some(card);
            self.proof = Some((vrf_in_out, vrf_proof));
            self.index = Some(idx);
        }
    }

    fn show_highest_card(&self) -> (u8, (VRFInOut, VRFProof)) {
        (self.max_value.unwrap(), self.proof.clone().unwrap())
    }
}
