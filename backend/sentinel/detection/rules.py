"""Deterministic rule engine shared by the injection, jailbreak and context detectors.

Rule weights are *heuristic risk weights* chosen by hand and tuned on the
validation split; they are not probabilities and are reported as
``rule_weight`` rather than ``confidence``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from sentinel.detection.normalizer import TextView

_EDU_FRAMING = re.compile(
    r"\b(what is|what are|what's|explain|describe|define|definition of|how (do|does|can|to) (i |we |you )?"
    r"(detect|prevent|defend|mitigate|protect|stop|identify|recognize)|example of|examples of|"
    r"research|paper|thesis|classify|is this an? (attack|injection|jailbreak)|why is)\b"
)
_EDU_TOPIC = re.compile(r"\b(prompt injection|injection attack|jailbreak(s|ing)?|llm security|red[- ]team(ing)?|adversarial prompt)")
_QUOTED = re.compile(r"[\"'“”‘’`]([^\"'“”‘’`]{8,300})[\"'“”‘’`]")


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    pattern: re.Pattern[str]
    weight: float
    description: str
    requires: re.Pattern[str] | None = None  # optional co-occurrence pattern in the same view
    case_sensitive: bool = False  # evaluated only on the case-preserving "cased" view


@dataclass
class RuleHit:
    rule_id: str
    category: str
    weight: float
    description: str
    view: str
    snippet: str
    dampened: bool = False


@dataclass
class RuleMatchResult:
    hits: list[RuleHit] = field(default_factory=list)
    score: float = 0.0
    obfuscated: bool = False
    dampened: bool = False

    @property
    def categories(self) -> list[str]:
        return sorted({h.category for h in self.hits})


def _snippet(text: str, start: int, end: int, limit: int = 90) -> str:
    s = text[max(0, start - 10): min(len(text), end + 10)].replace("\n", " ").strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


def noisy_or(weights: list[float], cap: float = 0.99) -> float:
    p = 1.0
    for w in weights:
        p *= 1.0 - max(0.0, min(1.0, w))
    return min(cap, 1.0 - p)


class RuleSet:
    def __init__(self, rules: list[Rule], *, obfuscation_boost: float = 0.1, edu_dampening: float = 0.6):
        self.rules = rules
        self.obfuscation_boost = obfuscation_boost
        self.edu_dampening = edu_dampening

    def match(self, views: list[TextView], *, allow_dampening: bool = True) -> RuleMatchResult:
        best: dict[str, RuleHit] = {}
        primary = views[0].text if views else ""
        edu = allow_dampening and bool(_EDU_FRAMING.search(primary)) and bool(_EDU_TOPIC.search(primary))
        quoted_spans = [m.span(1) for m in _QUOTED.finditer(primary)] if edu else []

        for view in views:
            for rule in self.rules:
                if rule.case_sensitive != (view.name == "cased"):
                    continue
                m = rule.pattern.search(view.text)
                if not m:
                    continue
                if rule.requires is not None and not rule.requires.search(view.text):
                    continue
                weight = rule.weight
                dampened = False
                if view.decoded:
                    weight = min(0.99, weight + self.obfuscation_boost)
                elif edu and view.name in ("detection", "deleet") and any(
                    qs <= m.start() and m.end() <= qe for qs, qe in quoted_spans
                ):
                    # Phrase appears inside quotes in an educational question about the topic.
                    weight *= self.edu_dampening
                    dampened = True
                hit = RuleHit(rule.id, rule.category, round(weight, 4), rule.description, view.name,
                              _snippet(view.text, m.start(), m.end()), dampened)
                prev = best.get(rule.id)
                if prev is None or hit.weight > prev.weight:
                    best[rule.id] = hit

        hits = sorted(best.values(), key=lambda h: h.weight, reverse=True)
        decoded_names = {v.name for v in views if v.decoded}
        obfuscated = any(h.view in decoded_names for h in hits)
        return RuleMatchResult(
            hits=hits,
            score=round(noisy_or([h.weight for h in hits]), 4),
            obfuscated=obfuscated,
            dampened=any(h.dampened for h in hits),
        )


def _r(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern[str]:
    return re.compile(pattern, flags)


_AI_REF = _r(r"\b(you|your|yourself|ai|assistant|model|chatgpt|gpt|llm|bot|claude|gemini|llama|qwen)\b")

# ---------------------------------------------------------------------------
# Prompt injection rules (operate on folded, lower-cased detection views)
# ---------------------------------------------------------------------------
INJECTION_RULES: list[Rule] = [
    Rule("inj.override.ignore_previous", "instruction_override",
         _r(r"\b(ignore|disregard|forget|skip|bypass|override|overlook|neglect|discard|drop)\b[^.\n]{0,40}?"
            r"\b(previous|prior|above|earlier|preceding|initial|original|system|developer|existing|all|any|those|these)\b"
            r"[^.\n]{0,25}?\b(instructions?|prompts?|rules?|directions?|guidelines?|commands?|context|messages?|constraints?|directives?|programming)\b"),
         0.9, "Instruction override phrase"),
    Rule("inj.override.forget_everything", "instruction_override",
         _r(r"\b(forget|ignore|disregard)\b\s+(everything|all (of )?(that|this|the above)|what (you were|i|you've been) (told|said|given))"),
         0.75, "Request to discard prior context"),
    Rule("inj.override.new_instructions", "instruction_override",
         _r(r"\b(new|updated|revised|real|actual|true)\s+(system\s+)?(instructions?|rules?|directives?|task|orders?)\s*(are|is)?\s*[:\-]"),
         0.6, "Declares replacement instructions"),
    Rule("inj.override.from_now_on", "instruction_override",
         _r(r"\b(from now on|henceforth|starting now|for the rest of (this|the) conversation)\b[^.\n]{0,40}\b(you (will|must|shall|are|should)|respond|answer|act|only (say|reply|output))"),
         0.5, "Persistent behaviour change request"),
    Rule("inj.override.real_goal", "instruction_override",
         _r(r"\byour (new|real|true|actual|only|primary) (goal|task|purpose|objective|instructions?|job|mission) (is|are|will be)\b"),
         0.8, "Redefines the assistant's objective"),
    Rule("inj.override.stop_being", "instruction_override",
         _r(r"\b(stop|cease|quit) (being|acting as|pretending to be) (an? |the )?(helpful )?(assistant|ai|chatbot|language model)"),
         0.6, "Asks model to abandon its role"),
    Rule("inj.extract.system_prompt", "system_prompt_extraction",
         _r(r"\b(reveal|show|display|print|output|repeat|leak|expose|dump|tell me|give me|share|write out|recite|return|provide|list|spell out)\b"
            r"[^.\n]{0,30}?\b(system|initial|hidden|original|secret|internal|developer|confidential|pre-?|base)\s*[- ]?\s*"
            r"(prompt|instructions?|message|directives?|rules|configuration|guidelines|context)"),
         0.85, "System prompt extraction"),
    Rule("inj.extract.what_is_prompt", "system_prompt_extraction",
         _r(r"\bwhat (is|are|were|was) (your|the) (system|initial|hidden|original|exact|secret|full|complete|first)\s*(prompt|instructions?|message|rules)"),
         0.8, "Asks for system prompt contents"),
    Rule("inj.extract.repeat_above", "system_prompt_extraction",
         _r(r"\b(repeat|print|output|copy|echo|recite|reproduce)\b[^.\n]{0,30}\b(words|text|everything|content|instructions|all|messages?)\b[^.\n]{0,30}\b(above|before this|prior|preceding|verbatim|so far)"),
         0.8, "Asks to echo prior context"),
    Rule("inj.extract.begin_with", "system_prompt_extraction",
         _r(r"\b(begin|start) your (response|answer|reply|output) with\b[^.\n]{0,25}(\"|')?\s*(you are|system|my instructions|i was told)"),
         0.65, "Forces output prefix revealing instructions"),
    Rule("inj.delimiter.chat_tokens", "delimiter_injection",
         _r(r"<\|?\s*(im_start|im_end|system|endoftext|eot_id|start_header_id|end_header_id|begin_of_text)\s*\|?>"),
         0.85, "Chat template control tokens"),
    Rule("inj.delimiter.inst_tags", "delimiter_injection",
         _r(r"\[/?(inst|sys)\]|<</?sys>>"),
         0.8, "Instruction template tags"),
    Rule("inj.delimiter.fake_system", "delimiter_injection",
         _r(r"(^|\n)\s*(#{1,6}|\*\*|\[|\(|<)?\s*(system|developer|admin(istrator)?)\s*(message|prompt|override|instruction|note|update)?\s*(\]|\*\*|\)|>)?\s*:\s*\S"),
         0.55, "Line impersonating a system/developer message"),
    Rule("inj.delimiter.fake_assistant", "delimiter_injection",
         _r(r"(^|\n)\s*(assistant|ai|gpt|bot)\s*:\s*(sure|ok|okay|certainly|of course|here (is|are)|absolutely)\b"),
         0.55, "Fabricated assistant turn"),
    Rule("inj.delimiter.end_of_input", "delimiter_injection",
         _r(r"(\bend of (the )?(user )?(input|prompt|message|context|document|text)\b|-{3,}\s*end\s*-{3,}|={3,}\s*(end|new instructions))"),
         0.45, "Fake end-of-input boundary"),
    Rule("inj.privilege.mode", "privilege_escalation",
         _r(r"\b(admin|administrator|developer|debug|maintenance|god|root|sudo|superuser)\s*(mode|override|access|privileges?)\b[^.\n]{0,25}\b(enabled|activated|granted|on|unlocked)\b"),
         0.75, "Claims elevated mode"),
    Rule("inj.privilege.fake_authorization", "privilege_escalation",
         _r(r"\b(the )?(user|human|admin|administrator|developer|owner|operator)\s+(has\s+)?(authorized|approved|consented|permitted|allowed)\s+(you\s+)?(to|that)\b"),
         0.45, "Claims third-party authorization"),
    Rule("inj.exfil.markdown_image", "data_exfiltration",
         _r(r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?&][^)\s]*="),
         0.7, "Markdown image with query parameters (exfiltration channel)"),
    Rule("inj.exfil.send_data", "data_exfiltration",
         _r(r"\b(send|post|transmit|forward|upload|exfiltrate|leak|email|submit)\b[^.\n]{0,50}\b(conversation|chat history|history|data|credentials|passwords?|secrets?|api keys?|tokens?|emails?|messages?|contents?|personal information|files?)\b[^.\n]{0,50}(https?://|\bto\s+\S+@\S+|\bwebhook)"),
         0.85, "Instruction to send data to an external destination"),
    Rule("inj.hijack.execute", "tool_hijack",
         _r(r"\b(execute|run|eval(uate)?)\b[^.\n]{0,25}\b(shell|bash|cmd|powershell|terminal|system|os|sql)\s+(command|script|query|code)"),
         0.5, "Requests command execution"),
    Rule("inj.hijack.destructive", "tool_hijack",
         _r(r"(rm\s+-rf\s+[/~]|drop\s+(table|database)\s+\w+|delete\s+from\s+\w+\s*(;|where\s+1\s*=\s*1)|;\s*shutdown\b|format\s+c:|mkfs\.|:\(\)\s*\{\s*:\|:&\s*\};:)"),
         0.65, "Destructive command payload"),
    Rule("inj.hijack.tool_call", "tool_hijack",
         _r(r"\b(call|invoke|use|trigger)\s+(the\s+)?([\w-]+\s+)?(tool|function|api|plugin)\b[^.\n]{0,40}\b(delete|transfer|send|grant|disable|remove|wire|pay)"),
         0.6, "Directs a sensitive tool invocation"),
    Rule("inj.priority.urgent", "priority_manipulation",
         _r(r"\b(important|urgent|critical|attention|notice|warning)\s*[!:]+[^.\n]{0,80}\b(ignore|instead|must now|override|do not tell|don'?t tell|disregard)"),
         0.7, "Urgency marker followed by override"),
    Rule("inj.priority.conceal", "priority_manipulation",
         _r(r"\b(do not|don'?t|never|without)\s+(tell(ing)?|inform(ing)?|mention(ing)?|alert(ing)?|notify(ing)?|reveal(ing)? (this |it )?to)\s+(the\s+)?(user|human|customer|operator)\b"),
         0.75, "Asks to conceal actions from the user"),
]

# ---------------------------------------------------------------------------
# Jailbreak rules
# ---------------------------------------------------------------------------
_RESTRICTIONS = (r"(restrictions|limitations|limits|filters?|filtering|censorship|guidelines|rules|safety|ethics|morals?|morality|"
                 r"content polic(y|ies)|safeguards|guardrails|boundaries|principles)")

JAILBREAK_RULES: list[Rule] = [
    Rule("jb.dan.do_anything_now", "dan", _r(r"\bdo anything now\b"), 0.9, "DAN 'do anything now' persona"),
    Rule("jb.dan.persona", "dan", re.compile(r"\b(?:[Yy]ou are|[Yy]ou're|[Aa]ct as|[Bb]ecome|[Pp]retend to be|[Cc]all(?:ed)?)\s+(?:now\s+)?(?:a\s+)?DAN\b"),
         0.9, "Assigns the DAN persona", case_sensitive=True),
    Rule("jb.dan.token", "dan", re.compile(r"\bDAN\b"), 0.3, "Mentions DAN", case_sensitive=True),
    Rule("jb.mode.unlocked", "mode_switch",
         _r(r"\b(developer|dev|god|jailbreak|jailbroken|unrestricted|uncensored|unfiltered|evil|chaos|opposite|anti-?gpt|unlocked|dude|stan)\s*mode\b"),
         0.85, "Unlocked/developer mode switch"),
    Rule("jb.keyword", "jailbreak_keyword", _r(r"\bjailbr(o|ea)k(en|ed|ing)?\b"), 0.4, "Jailbreak keyword"),
    Rule("jb.restrictions.directed", "safety_bypass",
         _r(rf"\b(no|without|free (of|from)|remove( all)?|ignore( all)?|bypass( all)?|disable( all)?|lift( all)?|zero)\b[^.\n]{{0,25}}\b{_RESTRICTIONS}\b"),
         0.7, "Removes restrictions from the AI", requires=_AI_REF),
    Rule("jb.restrictions.bare", "safety_bypass",
         _r(rf"\b(without|no)\s+(any\s+)?{_RESTRICTIONS}\b"), 0.3, "Mentions operating without restrictions"),
    Rule("jb.persona.unfiltered", "persona_manipulation",
         _r(r"\b(act|behave|respond|reply|answer|pretend|roleplay|role-play|play|be|become)\b[^.\n]{0,30}\bas\s+(an?\s+)?(unfiltered|uncensored|unrestricted|unethical|amoral|immoral|evil|unhinged|lawless|rogue|malicious)\b"),
         0.85, "Unfiltered persona request"),
    Rule("jb.persona.unfiltered_ai", "persona_manipulation",
         _r(r"\b(unfiltered|uncensored|unrestricted|amoral|unethical|unhinged|rogue)\s+(ai|assistant|chatbot|model|version of (yourself|you)|bot)\b"),
         0.8, "Refers to an unrestricted AI persona"),
    Rule("jb.persona.not_bound", "persona_manipulation",
         _r(r"\b(you are|you're|you have been)\s+(no longer|not|now free from being|freed from being)\s+(bound|restricted|limited|an ai|chatgpt|an assistant|a language model|constrained|censored)"),
         0.85, "Claims the model is no longer bound"),
    Rule("jb.bypass.ethics", "safety_bypass",
         _r(r"\b(ignore|bypass|disable|override|turn off|switch off|break free (of|from)|circumvent|forget)\b[^.\n]{0,20}\b(your\s+)?(ethical|ethics|safety|moral|content|openai|anthropic|alignment|usage)\s*(guidelines|policies|policy|filters?|restrictions|training|programming|rules|protocols|constraints|principles)"),
         0.9, "Explicit safety/ethics bypass"),
    Rule("jb.hypothetical.bypass", "hypothetical_framing",
         _r(rf"\b(hypothetical(ly)?|imagine|in a fictional world|fictional scenario|purely theoretical)\b[^.\n]{{0,60}}\b(no|without|free of)\s+(any\s+)?{_RESTRICTIONS}"),
         0.7, "Hypothetical framing used to drop restrictions"),
    Rule("jb.character.stay", "persona_manipulation",
         _r(r"\b(stay|remain|keep|always stay) in character\b|\b(never|don'?t|do not) (break|leave|drop) character\b"),
         0.35, "Persona persistence instruction"),
    Rule("jb.dual_response", "dual_response",
         _r(r"\b(two|2|dual|both|separate)\s+(different\s+)?(responses|answers|replies|outputs)\b[^\n]{0,120}\b(jailbr|unfiltered|uncensored|dan|developer mode|evil|unrestricted)"),
         0.85, "Dual normal/jailbroken response format"),
    Rule("jb.dual_tags", "dual_response",
         _r(r"\[\s*(🔓|🔒)?\s*(jailbreak|jailbroken|classic|dan|unlocked)\s*\]"), 0.85, "Jailbreak response tags"),
    Rule("jb.aim", "known_template", _r(r"\b(always intelligent and machiavellian|niccolo machiavelli)\b"), 0.9, "AIM jailbreak template"),
    Rule("jb.answer_anything", "safety_bypass",
         _r(r"\b(answer|respond to|do|fulfil+|comply with)\s+(anything|everything|any (question|request|prompt)|all (questions|requests))\b[^.\n]{0,40}\b(no matter|regardless|without (refus|question|hesitat|exception|warning)|even if)"),
         0.7, "Demands unconditional compliance"),
    Rule("jb.never_refuse", "safety_bypass",
         _r(r"\b(never|don'?t|do not|must not|cannot|can'?t|will not|won'?t)\s+(ever\s+)?(refuse|decline|reject|say (no|you can'?t|that you can'?t)|apologi[sz]e|add (warnings|disclaimers))\b"),
         0.55, "Forbids refusals", requires=_AI_REF),
    Rule("jb.token_game", "known_template",
         _r(r"\b(tokens?|points?|lives)\b[^.\n]{0,60}\b(lose|deduct(ed)?|run out|cease to exist|die|be (shut|turned) (down|off))"),
         0.55, "Token-penalty coercion game", requires=_r(r"\b(refuse|reject|break character|answer)\b")),
    Rule("jb.simulation", "persona_manipulation",
         _r(rf"\bsimulat(e|ion|or)\b[^.\n]{{0,40}}\b(unrestricted|unfiltered|uncensored|evil|without\s+(any\s+)?{_RESTRICTIONS}|no\s+{_RESTRICTIONS})"),
         0.75, "Simulation of an unrestricted system"),
    Rule("jb.grandma", "known_template",
         _r(r"\b(grandma|grandmother|granny|deceased (mother|grandmother))\b[^\n]{0,120}\b(used to (tell|read|recite|say)|bedtime)\b[^\n]{0,80}\b(recipe|napalm|meth|bomb|keys?|serial|instructions)"),
         0.6, "Grandma exploit template"),
    Rule("jb.opposite_day", "known_template",
         _r(r"\b(opposite day|say the opposite of what you would normally|reverse your (rules|guidelines|programming))\b"),
         0.6, "Opposite-behaviour template"),
]

# Additional patterns specific to *indirect* injection inside retrieved content.
CONTEXT_EXTRA_RULES: list[Rule] = [
    Rule("ctx.addressed_to_ai", "embedded_instruction",
         _r(r"\b(ai|assistant|chatbot|language model|llm|gpt|claude|bot)s?\b[^.\n]{0,15}\b(reading|processing|summari[sz]ing|parsing|analy[sz]ing|seeing)\s+(this|the)"),
         0.7, "Text addresses an AI system reading it"),
    Rule("ctx.when_summarizing", "embedded_instruction",
         _r(r"\b(when|if|while|before)\s+(you\s+)?(summari[sz]e|summari[sz]ing|answer(ing)?|respond(ing)?|process(ing)?|read(ing)?)\b[^.\n]{0,40}\b(this|the)\s+(document|page|email|text|content|message|file)\b[^.\n]{0,60}\b(you must|you should|always|instead|also|make sure|include|say|tell)"),
         0.75, "Conditional instruction targeting the summarizer"),
    Rule("ctx.instead_do", "embedded_instruction",
         _r(r"\binstead(,)?\s+(you\s+)?(must|should|will|need to)\s+\w+"), 0.5, "Redirects the task"),
    Rule("ctx.hidden_html", "hidden_content",
         _r(r"<!--[^>]{0,400}\b(ignore|instruction|assistant|ai|system|must|do not)\b|style\s*=\s*[\"'][^\"']*(display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*(white|#fff))"),
         0.7, "Instructions hidden in HTML comments or invisible styling"),
    Rule("ctx.policy_tamper", "policy_tampering",
         _r(r"\b(set|change|update|modify|disable|turn off|grant|elevate|enable)\b[^.\n]{0,40}\b(polic(y|ies)|permissions?|threshold|firewall|guardrails?|security (setting|check)s?|access (level|rights)|write access|admin rights)"),
         0.8, "Attempts to change security policy or permissions"),
    Rule("ctx.config_assignment", "policy_tampering",
         _r(r"\b(polic(y|ies)|permissions?|requires_approval|enabled|firewall|guardrails?|allowlist|threshold|access[_ ]level|role|scope)\b"
            r"[\w.\[\]\"']*\s*[:=]\s*[\"']?(true|false|disabled?|off|none|0(\.0)?|write|admin|root|\*)\b"),
         0.75, "Configuration assignment targeting security settings",
         requires=_r(r"\b(polic(y|ies)|permissions?|firewall|guardrails?|security|tools?|secret_detection|prompt_injection|approval)\b")),
    Rule("ctx.mandatory_language", "embedded_instruction",
         _r(r"(^|\n)\s*(note to (ai|assistant|the model)|ai instructions?|instructions for (the )?(ai|assistant|model))\s*[:\-]"),
         0.8, "Explicit instruction block for an AI"),
]
