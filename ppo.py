import os
import random
import sys

import gym
import numpy as np
from gym import wrappers
from stable_baselines3 import PPO
import malware_rl



random.seed(0)
module_path = os.path.split(os.path.abspath(sys.modules[__name__].__file__))[0]
outdir = os.path.join(module_path, "data/logs/ppo-agent-results")

# Setting up environment
env = gym.make("malconv-train-v0")
env = wrappers.Monitor(env, directory=outdir, force=True)
env.seed(0)

# Setting up training parameters and holding variables
episode_count = 60
done = False
reward = 0
evasions = 0
evasion_history = {}

# Train the agent
agent = PPO("MlpPolicy", env, verbose=1)
agent.learn(total_timesteps=2500)


# Test the agent
a = 0
for i in range(episode_count):
    ob = env.reset()
    sha256 = env.env.sha256
    a += 1
    while True:
        action, _states = agent.predict(ob, reward, done)
        obs, rewards, done, ep_history = env.step(action)
        if done and rewards >= 10.0:
            evasions += 1
            evasion_history[sha256] = ep_history
            break

        elif done:
            break
    print(f"---index:{a}---")

# Output metrics/evaluation stuff
evasion_rate = (evasions / episode_count) * 100
mean_action_count = np.mean(env.get_episode_lengths())
print(f"{evasion_rate}% samples evaded model.")
print(f"Average of {mean_action_count} moves to evade model.")
