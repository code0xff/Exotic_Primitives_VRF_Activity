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
        let (num, str) = player.reveal();

        let hash = hash_blake2(num, str);
        if commitals[idx] != hash {
            panic!("cheated player!!!");
        }

        seed += num;
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
        let max_draw = player.show_highest_card();
        let (vrf_in_out, vrf_proof) = max_draw.proof;
        let res = player.keypair.public.vrf_verify(
            context.bytes(&max_draw.index.to_le_bytes()),
            &VRFPreOut::from_bytes(&vrf_in_out.output.to_bytes()).unwrap(),
            &vrf_proof,
        );
        if res.is_ok() {
            println!("Player {player_idx} has max value {}", max_draw.value);
            if winner_value < max_draw.value {
                winner_value = max_draw.value;
                winner = player_idx;
            }
        } else {
            println!("Player {player_idx} tried to cheat, it's disqualified!")
        }
    }

    println!("Winner Player: {winner}");
}

fn hash_blake2(random_number: u32, random_string: String) -> [u8; 16] {
    sp_core::blake2_128(&format!("{random_number}{random_string}").into_bytes())
}

#[derive(Clone, Debug)]
struct MaxDraw {
    index: u32,
    value: u8,
    proof: (VRFInOut, VRFProof),
}

struct Player {
    keypair: Keypair,
    commitment: Option<(u32, String)>,
    max_draw: Option<MaxDraw>,
}

impl Player {
    fn new() -> Self {
        Self {
            keypair: Keypair::generate(),
            commitment: None,
            max_draw: None,
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
        self.commitment = Some((random_number, random_string));
        hash
    }

    fn reveal(&self) -> (u32, String) {
        self.commitment.clone().unwrap()
    }

    fn draw(&mut self, idx: u32) {
        let context = signing_context("".as_bytes());
        let (vrf_in_out, vrf_proof, _) = self.keypair.vrf_sign(context.bytes(&idx.to_le_bytes()));
        let card = vrf_in_out.as_output_bytes()[0] % 52;

        self.max_draw = Some(match &self.max_draw {
            Some(max_draw) if max_draw.value > card => max_draw.clone(),
            _ => MaxDraw {
                index: idx,
                proof: (vrf_in_out, vrf_proof),
                value: card,
            },
        })
    }

    fn show_highest_card(&self) -> MaxDraw {
        self.max_draw.clone().unwrap()
    }
}
