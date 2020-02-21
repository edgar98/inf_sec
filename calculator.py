import kivy
import re
from kivy.properties import NumericProperty
from kivy.properties import StringProperty

kivy.require("1.11.1")

from kivy.app import App
from kivy.uix.accordion import Accordion, AccordionItem
from kivy.core.window import Window
from kivy.logger import Logger
from kivy.uix.tabbedpanel import TabbedPanel


def f(x):
    return 0 if x == 0 else 1.176


class SampTabPanel(TabbedPanel):
    base_score = NumericProperty(0)
    temporal_score = NumericProperty(0)
    environmental_score = NumericProperty(0)
    base_score_v3 = NumericProperty(0)
    temporal_score_v3 = NumericProperty(0)
    environmental_score_v3 = NumericProperty(0)
    next_value = StringProperty('')
    vals = {
        "av": 0,
        "ac": 0,
        "au": 0,
        "c": 0,
        "i": 0,
        "exp": 0.0,
        "rl": 0,
        "rc": 0,
        "a": 0,
        "cdp": 0,
        "td": 0,
        "cr": 0,
        "ir": 0,
        "ar": 0
    }
    vals_v3 = {
        "av": "n",
        "ac": 'l',
        "pr": 'n',
        "ui": 'n',
        "s": 'u',
        "c": 'n',
        "i": 'n',
        "a": 'n',
        "e": 'x',
        "rl": 'x',
        "rc": 'x',
        "mav": 'x',
        "mac": 'x',
        "mpr": 'x',
        "mui": 'x',
        "ms": 'x',
        "mc": 'x',
        "mi": 'x',
        "ma": 'x',
        "cr": 'x',
        "ir": 'x',
        "ar": 'x',
    }

    cvss_v3 = {
        "av": {
            'n': 0.85,
            'a': 0.62,
            'l': 0.55,
            'p': 0.2,
        },
        "ac": {
            'l': 0.77,
            'h': 0.44,
        },
        "pr": {
            'n': 0.85,
            'l': [0.62, 0.68],
            'h': [0.27, 0.50],
        },
        "ui": {
            'n': 0.85,
            'r': 0.62,
        },
        "s": {
            'u': 0,
            'c': 1,
        },
        "c": {
            'n': 0,
            'l': 0.22,
            'h': 0.56,
        },
        "i": {
            'n': 0,
            'l': 0.22,
            'h': 0.56,
        },
        "a": {
            'n': 0,
            'l': 0.22,
            'h': 0.56,
        },
        "e": {
            'x': 1,
            'u': 0.91,
            'p': 0.94,
            'f': 0.97,
            'h': 1,
        },
        "rl": {
            'x': 1,
            'o': 0.95,
            't': 0.96,
            'w': 0.97,
            'u': 1,
        },
        "rc": {
            'x': 1,
            'u': 0.92,
            'r': 0.96,
            'c': 1,
        },
        "mav": {
            'x': 'av',
            'n': 0.85,
            'a': 0.62,
            'l': 0.55,
            'p': 0.2,
        },
        "mac": {
            'x': 'ac',
            'l': 0.77,
            'h': 0.44,
        },
        "mpr": {
            'x': 'pr',
            'n': 0.85,
            'l': [0.62, 0.68],
            'h': [0.27, 0.50],
        },
        "mui": {
            'x': 'ui',
            'n': 0.85,
            'r': 0.62,
        },
        "ms": {
            'x': 's',
            'u': 0,
            'c': 1,
        },
        "mc": {
            'x': 'c',
            'n': 0,
            'l': 0.22,
            'h': 0.56,
        },
        "mi": {
            'x': 'i',
            'n': 0,
            'l': 0.22,
            'h': 0.56,
        },
        "ma": {
            'x': 'a',
            'n': 0,
            'l': 0.22,
            'h': 0.56,
        },
        "cr": {
            'x': 1,
            'h': 1.5,
            'm': 1,
            'l': 0.5,
        },
        "ir": {
            'x': 1,
            'h': 1.5,
            'm': 1,
            'l': 0.5,
        },
        "ar": {
            'x': 1,
            'h': 1.5,
            'm': 1,
            'l': 0.5,
        },
    }

    def create_vals_v3(self):
        for key in self.vals_v3.keys():
            if not isinstance(self.vals_v3[key], type('a')):
                continue
            vals_value = self.vals_v3[key]
            cvss_value = self.cvss_v3[key]
            value_to_insert = cvss_value[vals_value]
            if isinstance(value_to_insert, type('a')):
                value_to_insert = self.vals_v3[value_to_insert]
            if isinstance(value_to_insert, type([])):
                if key == 'pr':
                    value_to_insert = value_to_insert[self.vals_v3['s']]
                elif key == 'mpr':
                    value_to_insert = value_to_insert[self.vals_v3['ms']]
            self.vals_v3[key] = value_to_insert

    def calculate_base_score(self):
        vals = self.vals
        impact = 10.41 * (1 - (1 - vals['c']) * (1 - vals['i']) * (1 - vals['a']))
        exploitability = 20 * vals['av'] * vals['ac'] * vals['au']
        self.base_score = round(((0.6 * impact) + (0.4 * exploitability) - 1.5) * f(impact), 1)

    def calculate_temporal_score(self):
        vals = self.vals
        self.temporal_score = round(self.base_score * vals['exp'] * vals['rl'] * vals['rc'], 1)

    def calculate_environmental_score(self):
        vals = self.vals
        adjusted_impact = 10 if 10 < 10.41 * (1 - (1 - vals['c'] * vals['cr']) * (1 - vals['i'] * vals['ir']) *
                                              (1 - vals['a'] * vals['ar'])) else 10.41 * (
                1 - (1 - vals['c'] * vals['cr']) * (1 - vals['i'] * vals['ir']) *
                (1 - vals['a'] * vals['ar']))
        exploitability = 20 * vals['av'] * vals['ac'] * vals['au']
        impact = 10.41 * (1 - (1 - vals['c']) * (1 - vals['i']) * (1 - vals['a']))
        adjusted_base_score = (((0.6 * adjusted_impact) + (0.4 * exploitability) - 1.5) * f(impact))
        adjusted_temporal = adjusted_base_score * vals['exp'] * vals['rl'] * vals['rc']
        self.environmental_score = round(
            (adjusted_temporal + (10 - adjusted_temporal) * vals['cdp']) * vals['td'], 1)

    def calculate(self, group, value):
        self.vals[group] = value
        self.calculate_base_score()
        self.calculate_temporal_score()
        self.calculate_environmental_score()

    def calculate_base_score_v3(self):
        vals = self.vals_v3
        impact_base = 1 - ((1 - vals['c']) * (1 - vals['i']) * (1 - vals['a']))
        exploitability = 8.22 * vals['av'] * vals['ac'] * vals['pr'] * vals['ui']
        if vals['s'] == 0:
            impact = 6.42 * impact_base
        elif vals['s'] == 1:
            impact = 7.52 * (impact_base - 0.029) - 3.25 * pow((impact_base - 0.02), 15)
        if impact <= 0:
            self.base_score_v3 = 0
        elif vals['s'] == 0:
            self.base_score_v3 = round(min((impact + exploitability), 10), 0)
        elif vals['s'] == 1:
            self.base_score_v3 = round(min(1.08 * (impact + exploitability), 10), 0)

    def calculate_temporal_score_v3(self):
        vals = self.vals_v3
        print((vals['e'], vals['rl'], vals['rc']))
        print(self.base_score_v3)
        self.temporal_score_v3 = round(self.base_score_v3 * vals['e'] * vals['rl'] * vals['rc'], 0)

    def calculate_environmental_score_v3(self):
        vals = self.vals_v3
        m_impact = 0
        m_impact_base = min((1 - (1 - vals['mc'] * vals['cr']) * (1 - vals['mi'] * vals['ir']) *
                             (1 - vals['ma'] * vals['ar'])), 0.915)
        m_exploitability = 8.22 * vals['mav'] * vals['mac'] * vals['mpr'] * vals['mui']

        if vals['ms'] == 0:
            m_impact = 6.42 * m_impact_base
        if vals['ms'] == 1:
            m_impact = 7.52 * (m_impact_base - 0.029) - 3.25 * pow((m_impact_base - 0.02), 15)

        if m_impact <= 0:
            self.environmental_score_v3 = 0
        elif vals['ms'] == 0:
            self.environmental_score_v3 = round(round(min((m_impact + m_exploitability), 10), 0) *
                                                vals['e'] * vals['rl'] * vals['rc'], 0)
        elif vals['ms'] == 1:
            self.environmental_score_v3 = round(round(min(1.08 * (m_impact + m_exploitability), 10), 0) *
                                                vals['e'] * vals['rl'] * vals['rc'], 0)

    def calculate_v3(self, text):
        group = re.findall(r'\((\D+)\:\D+\)', str(text).lower()).pop(0)
        value = re.findall(r'\(\D+\:(\D+)\)', str(text).lower()).pop(0)
        self.vals_v3[group] = value
        self.create_vals_v3()
        self.calculate_base_score_v3()
        self.calculate_temporal_score_v3()
        self.calculate_environmental_score_v3()


class SampAccordion(Accordion):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def _do_layout(self, dt):
        children = self.children
        if children:
            all_collapsed = all(x.collapse for x in children)
        else:
            all_collapsed = False

        # Changed below: if all items are collapsed, do nothing. This is what we want.
        if all_collapsed:
            children[len(children) - 1].collapse = False

        orientation = self.orientation
        min_space = self.min_space
        min_space_total = len(children) * self.min_space
        w, h = self.size
        x, y = self.pos
        if orientation == 'horizontal':
            display_space = self.width - min_space_total
        else:
            display_space = self.height - min_space_total

        if display_space <= 0:
            Logger.warning('Accordion: not enough space '
                           'for displaying all children')
            Logger.warning('Accordion: need %dpx, got %dpx' % (
                min_space_total, min_space_total + display_space))
            Logger.warning('Accordion: layout aborted.')
            return

        if orientation == 'horizontal':
            children = reversed(children)

        for child in children:
            child_space = min_space
            child_space += display_space * (1 - child.collapse_alpha)
            child._min_space = min_space
            child.x = x
            child.y = y
            child.orientation = self.orientation
            if orientation == 'horizontal':
                child.content_size = display_space, h
                child.width = child_space
                child.height = h
                x += child_space
            else:
                child.content_size = w, display_space
                child.width = w
                child.height = child_space
                y += child_space


class PopUpAccordionItem(AccordionItem):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.title_template = 'PopUpAccordionItemTitle'

    def on_touch_down(self, touch):
        if not self.collide_point(*touch.pos):
            return
        if self.disabled:
            return True
        if self.collapse:
            self.collapse = False
            return True
        # Changed below: if item is not collapsed and user clicked the title bar, collapse.
        if not self.collapse and self.container_title.collide_point(*touch.pos):
            self.collapse = True
        return super(AccordionItem, self).on_touch_down(touch)


class CalculatorApp(App):

    def build(self):
        Window.clearcolor = (0.5, 0.5, 0.5, 1)
        accordion = SampAccordion()
        return SampTabPanel()


if __name__ == '__main__':
    app = CalculatorApp()
    app.run()
