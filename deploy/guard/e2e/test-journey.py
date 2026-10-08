#!/usr/bin/env python3
"""Offline only: no subprocess, network, wallet or actual signed attestation."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
import tarfile
import tempfile
from decimal import Decimal
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from contextlib import ExitStack

BASE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('journey', BASE / 'journey.py')
j = importlib.util.module_from_spec(spec); spec.loader.exec_module(j)
CLIENT = '0x' + 'b' * 40


class BoundTests(unittest.TestCase):
    def test_plan_uses_exact_quantity_strings_and_fixed_price_below_cap(self):
        asset, plan = j.entry_plan(dict(universe=[dict(name='BTC', szDecimals=5)]), dict(BTC='100000'))
        self.assertEqual(asset, 0)
        self.assertEqual(plan['side'], 'buy')
        self.assertLessEqual(Decimal(plan['size']) * Decimal(plan['limit_price']), 15)
        self.assertEqual(plan['stop'], 'guard_policy')

    def test_plan_refuses_grid_below_minimum(self):
        with self.assertRaises(RuntimeError):
            j.entry_plan(dict(universe=[dict(name='BTC', szDecimals=0)]), dict(BTC='100000'))

    def test_plan_refuses_delisted_market(self):
        with self.assertRaises(RuntimeError):
            j.entry_plan(dict(universe=[dict(name='BTC', szDecimals=5, isDelisted=True)]), dict(BTC='100000'))

    def test_plan_refuses_ambiguous_market(self):
        with self.assertRaises(RuntimeError):
            j.entry_plan(dict(universe=[dict(name='BTC', szDecimals=5)] * 2), dict(BTC='100000'))

    def test_money_rejects_float_nonfinite_or_exponent(self):
        for value in (1.5, True, 'NaN', 'Infinity', '1e3', ''):
            with self.subTest(value=value), self.assertRaises(RuntimeError): j.decimal(value)


class OwnershipTests(unittest.TestCase):
    def setUp(self):
        self.plan = dict(size='0.00014', limit_price='100200')
        self.cloid = '0x7a6d' + '1' * 28
        self.order = dict(a=0, b=True, s='0.00014', p='100200', r=False, c=self.cloid)
        self.events = [dict(kind='decision', client=CLIENT, action='order', seq=1, request=dict(orders=[self.order])),
                       dict(kind='sent', decision=1, reply=dict(response=dict(data=dict(statuses=[dict(filled=dict(oid=10)), dict(resting=dict(oid=11))]))))]

    def test_owned_entry_and_child_oids_from_real_raw_reply_shape(self):
        self.assertEqual(j.ownership(self.events, CLIENT, 0, self.plan), (self.cloid, {10, 11}))

    def test_other_client_refused(self):
        with self.assertRaises(RuntimeError): j.ownership(self.events, '0x' + 'c' * 40, 0, self.plan)

    def test_multiple_opening_decisions_refused(self):
        self.events.append(copy.deepcopy(self.events[0]))
        with self.assertRaises(RuntimeError): j.ownership(self.events, CLIENT, 0, self.plan)

    def test_changed_quantity_refused(self):
        self.order['s'] = '1'
        with self.assertRaises(RuntimeError): j.ownership(self.events, CLIENT, 0, self.plan)

    def test_other_asset_refused(self):
        with self.assertRaises(RuntimeError): j.ownership(self.events, CLIENT, 1, self.plan)

    def test_other_cloid_prefix_refused(self):
        self.order['c'] = '0x' + 'f' * 32
        with self.assertRaises(RuntimeError): j.ownership(self.events, CLIENT, 0, self.plan)

    def test_unrelated_sent_event_oids_excluded(self):
        self.events.append(dict(kind='sent', decision=9, reply=dict(resting=dict(oid=999))))
        self.assertEqual(j.ownership(self.events, CLIENT, 0, self.plan)[1], {10, 11})

    def test_owned_serving_intent_oids_included(self):
        self.events.extend([dict(kind='intent', of=1, seq=2), dict(kind='sent', decision=2, reply=dict(resting=dict(oid=12)))])
        self.assertEqual(j.ownership(self.events, CLIENT, 0, self.plan)[1], {10, 11, 12})


class FillTests(unittest.TestCase):
    def setUp(self):
        self.plan = dict(size='0.00014')
        self.fills = [dict(oid=10, coin='BTC', side='B', sz='0.00014', px='100000')]
        self.positions = [dict(coin='BTC', szi='0.00014')]

    def test_owned_bounded_fill_and_position_accepted(self):
        self.assertEqual(j.owned_position(self.positions, self.fills, 10, self.plan), Decimal('0.00014'))

    def test_only_other_order_fill_refused(self):
        with self.assertRaises(RuntimeError): j.owned_position(self.positions, self.fills, 9, self.plan)

    def test_unrelated_position_refused(self):
        self.positions.append(dict(coin='ETH', szi='0.1'))
        with self.assertRaises(RuntimeError): j.owned_position(self.positions, self.fills, 10, self.plan)

    def test_added_net_quantity_refused(self):
        self.positions[0]['szi'] = '0.00015'
        with self.assertRaises(RuntimeError): j.owned_position(self.positions, self.fills, 10, self.plan)

    def test_short_position_refused(self):
        self.positions[0]['szi'] = '-0.00014'
        with self.assertRaises(RuntimeError): j.owned_position(self.positions, self.fills, 10, self.plan)

    def test_actual_notional_over_cap_refused(self):
        self.fills[0]['px'] = '1000000'
        with self.assertRaises(RuntimeError): j.owned_position(self.positions, self.fills, 10, self.plan)

    def test_unknown_or_float_fill_refused(self):
        self.fills[0]['sz'] = 0.00014
        with self.assertRaises(RuntimeError): j.owned_position(self.positions, self.fills, 10, self.plan)


class StopProofTests(unittest.TestCase):
    def setUp(self):
        self.plan = dict(size='0.00014', limit_price='100200')
        self.cloid = '0x7a6d' + '1' * 28
        self.stop_cloid = '0x7a67' + '2' * 28
        self.entry = dict(a=0, b=True, s='0.00014', p='100200', r=False, c=self.cloid)
        self.wire = dict(a=0, b=False, s='0.00014', p='88200', r=True, c=self.stop_cloid,
                         t=dict(trigger=dict(isMarket=True, triggerPx='98000', tpsl='sl')))
        self.decision = dict(kind='decision', client=CLIENT, action='order', seq=1,
                             request=dict(orders=[self.entry]),
                             forward=dict(type='order', grouping='normalTpsl', orders=[self.entry, self.wire]),
                             changes=['a reduce-only stop at 98000 (2% from 100000) is attached'])
        self.events = [self.decision, dict(kind='sent', decision=1, ok=True, reply=dict(status='ok', response=dict(type='order', data=dict(statuses=[dict(filled=dict(oid=10)), dict(resting=dict(oid=11))]))))]
        self.order = dict(oid=11, coin='BTC', side='A', sz='0.00014', cloid=self.stop_cloid,
                          isTrigger=True, reduceOnly=True, orderType='Stop Market', triggerPx='98000', limitPx='88200')

    def check(self):
        return j.protective_stop(self.events, CLIENT, 0, self.plan, [self.order], Decimal('0.00014'), 5, Decimal('100000'))

    def test_exact_durable_default_sl_and_venue_readback_accepted(self):
        self.assertIs(self.check(), self.order)

    def test_reviewer_take_profit_above_long_rejected(self):
        self.order.update(orderType='Take Profit Market', triggerPx='110000', limitPx='99000')
        with self.assertRaises(RuntimeError): self.check()

    def test_unknown_and_stop_limit_venue_classifications_rejected(self):
        for kind in ('Take Profit Market', 'Stop Limit', 'Unknown', '', None):
            with self.subTest(kind=kind):
                self.order['orderType'] = kind
                with self.assertRaises(RuntimeError): self.check()

    def test_durable_tp_even_with_matching_venue_rejected(self):
        self.wire['t']['trigger']['tpsl'] = 'tp'
        self.order['orderType'] = 'Take Profit Market'
        with self.assertRaises(RuntimeError): self.check()

    def test_durable_nonmarket_trigger_rejected(self):
        self.wire['t']['trigger']['isMarket'] = False
        with self.assertRaises(RuntimeError): self.check()

    def test_incorrect_venue_trigger_rejected(self):
        self.order['triggerPx'] = '97000'
        with self.assertRaises(RuntimeError): self.check()

    def test_incorrect_venue_limit_rejected(self):
        self.order['limitPx'] = '90000'
        with self.assertRaises(RuntimeError): self.check()

    def test_loose_wire_and_venue_both_matching_still_rejected(self):
        self.wire['t']['trigger']['triggerPx'] = '90000'; self.wire['p'] = '81000'
        self.order.update(triggerPx='90000', limitPx='81000')
        self.decision['changes'] = ['a reduce-only stop at 90000 (2% from 100000) is attached']
        with self.assertRaises(RuntimeError): self.check()

    def test_incorrect_default_percent_rejected(self):
        self.decision['changes'] = ['a reduce-only stop at 98000 (3% from 100000) is attached']
        with self.assertRaises(RuntimeError): self.check()

    def test_bogus_default_reference_outside_forwarded_entry_band_rejected(self):
        self.wire['t']['trigger']['triggerPx'] = '88200'; self.wire['p'] = '79380'
        self.order.update(triggerPx='88200', limitPx='79380')
        self.decision['changes'] = ['a reduce-only stop at 88200 (2% from 90000) is attached']
        with self.assertRaises(RuntimeError): self.check()

    def test_unprotected_forwarded_group_rejected(self):
        self.decision['forward']['grouping'] = 'na'
        with self.assertRaises(RuntimeError): self.check()

    def test_missing_default_reference_rejected(self):
        self.decision['changes'] = []
        with self.assertRaises(RuntimeError): self.check()

    def test_venue_quantity_bigger_or_smaller_than_forwarded_rejected(self):
        for quantity in ('0.00013', '0.00015'):
            with self.subTest(quantity=quantity):
                self.order['sz'] = quantity
                with self.assertRaises(RuntimeError): self.check()

    def test_wire_quantity_different_from_owned_opening_rejected(self):
        self.wire['s'] = '0.00015'
        with self.assertRaises(RuntimeError): self.check()

    def test_cloid_not_exact_durable_guard_cloid_rejected(self):
        self.order['cloid'] = '0x7a67' + '3' * 28
        with self.assertRaises(RuntimeError): self.check()

    def test_unowned_oid_rejected(self):
        self.order['oid'] = 12
        with self.assertRaises(RuntimeError): self.check()

    def test_wrong_asset_or_side_in_wire_rejected(self):
        for field, value in (('a', 1), ('b', True), ('r', False)):
            with self.subTest(field=field):
                old = self.wire[field]; self.wire[field] = value
                with self.assertRaises(RuntimeError): self.check()
                self.wire[field] = old

    def test_trigger_no_longer_below_live_mark_rejected(self):
        with self.assertRaises(RuntimeError):
            j.protective_stop(self.events, CLIENT, 0, self.plan, [self.order], Decimal('0.00014'), 5, Decimal('97000'))

    def test_venue_trigger_direction_when_present_must_agree(self):
        self.order['triggerCondition'] = 'Price above 98000'
        with self.assertRaises(RuntimeError): self.check()
        self.order['triggerCondition'] = 'Price below 98000'
        self.check()

    def test_grid_matches_source_significant_figures_and_decimal_caps(self):
        self.assertEqual(j.price_grid(Decimal('62345.67'), 5, up=True), Decimal('62346'))
        self.assertEqual(j.price_grid(Decimal('1234.56'), 5, up=False), Decimal('1234.5'))
        self.assertEqual(j.price_grid(Decimal('123456.7'), 5, up=False), Decimal('123456'))


class FinallyBoundaryTests(unittest.TestCase):
    def execute_lost_reply(self, *, missing_ownership=False, resting=False):
        with tempfile.TemporaryDirectory(dir=str(Path('/tmp').resolve())) as folder:
            base = Path(folder)
            args = SimpleNamespace(work=base / 'work', binary=base / 'not-executed', port=18547,
                                   account=CLIENT, api_wallet='0x' + 'd' * 40,
                                   tag='v1.0.1', source='a' * 40, expiry=j.time.time() + 1000)
            fixture = StopProofTests(); fixture.setUp()
            if resting:
                fixture.events[1]['reply']['response']['data']['statuses'] = [dict(resting=dict(oid=10)), 'waitingForFill']
                fixture.order = dict(oid=10, coin='BTC', side='B', sz='0.00014', cloid=fixture.cloid,
                                     isTrigger=False, reduceOnly=False, orderType='Limit', limitPx='100200')
            actions = []; state = dict(closed=False, cancelled=False)
            guard = Mock(pid=12345); guard.returncode = None
            guard.poll.side_effect = lambda: guard.returncode
            guard.wait.side_effect = lambda timeout: setattr(guard, 'returncode', 0)
            class Reads:
                flat_observation = dict(dexes=[''])
                def __init__(self, account): pass
                def flat_all(self): return True
                def json(self, url): return [] if missing_ownership else fixture.events
                def info(self, kind, **kwargs):
                    if kind == 'meta': return dict(universe=[dict(name='BTC', szDecimals=5)])
                    if kind == 'allMids': return dict(BTC='100000')
                    if kind == 'orderStatus':
                        if kwargs.get('oid') == fixture.stop_cloid:
                            return dict(status='order', order=dict(status='open', order=copy.deepcopy(fixture.order)))
                        return dict(status='order', order=dict(status='open', order=copy.deepcopy(fixture.order) if resting else dict(oid=10)))
                    if kind == 'userFillsByTime': return [] if resting else [dict(oid=10, coin='BTC', side='B', sz='0.00014', px='100000')]
                    raise AssertionError('Unexpected fake read')
                def holdings(self):
                    positions = [] if resting or state['closed'] else [dict(coin='BTC', szi='0.00014', positionValue='14', leverage=dict(type='isolated'))]
                    orders = [] if state['cancelled'] else [fixture.order]
                    return positions, orders, Decimal('2')
            class MCP:
                def __init__(self, *unused): pass
                def stop(self): actions.append('stop-mcp')
                def tool(self, name, arguments=None):
                    actions.append(name)
                    if name == 'place_order':
                        if resting: return dict(sent=True, venue_statuses=[dict(status='resting')]), False
                        raise RuntimeError('Offline lost reply fixture')
                    if name == 'preview_order': return dict(preview=dict(verdict='allow')), False
                    if name == 'close_position': state['closed'] = True
                    if name == 'cancel_order': state['cancelled'] = True
                    return dict(ok=True), False
            def admitted(unused):
                args.work.mkdir(mode=0o700); args.binary_hash = 'offline'
                return dict(tag=args.tag, source=args.source)
            def initialized(*unused, **kwargs):
                home = args.work / 'home'
                (home / 'guard.toml').write_text('mode="testnet"\nnetwork="testnet"\naccount="' + CLIENT
                    + '"\nlisten="127.0.0.1:18547"\n[auth]\nclients=["' + CLIENT + '"]\n')
                (home / 'guard.toml').chmod(0o600)
                (args.work / 'client.key').write_text('offline non-key fixture'); (args.work / 'client.key').chmod(0o600)
                return SimpleNamespace(returncode=0)
            with ExitStack() as stack:
                for name, value in (('binding', admitted), ('Reads', Reads), ('MCP', MCP), ('digest', lambda path: 'offline'),
                                    ('status', lambda *unused: dict(started_at_ms=int(j.time.time() * 1000)))):
                    stack.enter_context(patch.object(j, name, value))
                stack.enter_context(patch.object(j.subprocess, 'run', side_effect=initialized))
                stack.enter_context(patch.object(j.subprocess, 'Popen', return_value=guard))
                killed = stack.enter_context(patch.object(j.os, 'killpg'))
                stack.enter_context(patch.object(j.signal, 'signal'))
                stack.enter_context(patch.object(j.time, 'sleep'))
                with self.assertRaises(RuntimeError): j.main(args)
                report = json.loads((args.work / 'receipt.json').read_text())
                calls = killed.call_count
            return report, actions, calls

    def test_lost_opening_reply_enters_owned_reduce_only_cleanup_without_retry_or_pass(self):
        report, actions, signals = self.execute_lost_reply()
        self.assertEqual(actions.count('place_order'), 1)
        self.assertEqual(actions.count('close_position'), 1)
        self.assertEqual(actions.count('cancel_order'), 1)
        self.assertTrue(report['cleanup_complete'])
        self.assertFalse(report['journey_passed'])
        self.assertGreater(signals, 0)

    def test_resting_unfilled_entry_is_cancelled_without_retry_close_or_journey_credit(self):
        report, actions, signals = self.execute_lost_reply(resting=True)
        self.assertEqual(actions.count('place_order'), 1)
        self.assertEqual(actions.count('cancel_order'), 1)
        self.assertNotIn('close_position', actions)
        self.assertTrue(report['cleanup_complete'])
        self.assertFalse(report['journey_passed'])
        self.assertEqual(report['failure_stage'], 'entry_submission')
        self.assertEqual(report['failure_code'], 'journey_entry_submission')
        self.assertGreater(signals, 0)

    def test_redacted_failure_codes_contain_no_exception_values(self):
        report, actions, signals = self.execute_lost_reply(missing_ownership=True)
        self.assertEqual(report['cleanup_failure_code'], 'cleanup_resolve_owned_protection')
        self.assertNotIn('Offline lost reply fixture', json.dumps(report))

    def test_lost_reply_missing_ownership_keeps_guard_and_never_closes_unrelated_exposure(self):
        report, actions, signals = self.execute_lost_reply(missing_ownership=True)
        self.assertEqual(actions.count('place_order'), 1)
        self.assertNotIn('close_position', actions)
        self.assertNotIn('cancel_order', actions)
        self.assertTrue(report['cleanup_blocked_requires_parent'])
        self.assertFalse(report['cleanup_complete'])
        self.assertFalse(report['journey_passed'])
        self.assertEqual(signals, 0)


class DeferredStopResolutionTests(unittest.TestCase):
    def setUp(self):
        fixture = StopProofTests(); fixture.setUp()
        self.fixture = fixture
        self.plan = dict(size='0.00018', limit_price='82546')
        fixture.plan = self.plan
        fixture.entry.update(a=3, s='0.00018', p='82546', c='0x7a6d000000000000000001a11d7f9167')
        fixture.cloid = fixture.entry['c']
        fixture.wire.update(a=3, s='0.00018', p='72660', c='0x7a674d0dd0eefd885d90a5777b6026c1')
        fixture.stop_cloid = fixture.wire['c']; fixture.wire['t']['trigger']['triggerPx'] = '80734'
        fixture.decision['changes'] = ['a reduce-only stop at 80734 (2% from 82381.5) is attached']
        fixture.events[1]['reply']['response']['data']['statuses'] = [dict(filled=dict(oid=62205898480, totalSz='0.00018', avgPx='82386.0', cloid=fixture.cloid)), 'waitingForTrigger']
        fixture.order.update(oid=62205898481, sz='0.00018', cloid=fixture.stop_cloid,
                             triggerPx='80734.0', limitPx='72660.0', triggerCondition='Price below 80734',
                             origSz='0.00018', timestamp=1791496264699, children=[], isPositionTpsl=False, tif=None)
        self.stop_status = dict(status='order', order=dict(status='open', statusTimestamp=1791496264699, order=copy.deepcopy(fixture.order)))
        self.entry_status = dict(status='order', order=dict(status='filled', order=dict(oid=62205898480)))
        self.positions = [dict(coin='BTC', szi='0.00018', positionValue='14.82948', leverage=dict(type='isolated'))]
        self.orders = [copy.deepcopy(fixture.order)]
        self.fills = [dict(oid=62205898480, coin='BTC', side='B', sz='0.00018', px='82386.0')]
        self.calls = []
        outer = self
        class Reads:
            def info(self, kind, **fields):
                outer.calls.append((kind, fields))
                if kind == 'orderStatus':
                    if fields['oid'] == fixture.cloid: return copy.deepcopy(outer.entry_status)
                    if fields['oid'] == fixture.stop_cloid: return copy.deepcopy(outer.stop_status)
                    raise AssertionError('Lookup did not use an exact durable cloid.')
                if kind == 'userFillsByTime': return copy.deepcopy(outer.fills)
                raise AssertionError('Unexpected synthetic read.')
            def holdings(self): return copy.deepcopy(outer.positions), copy.deepcopy(outer.orders), Decimal('100')
        self.reads = Reads(); self.args = SimpleNamespace(account=CLIENT)
    def resolve(self, *, cleanup=False):
        return j.resolved_ownership(self.reads, self.args, self.fixture.events, CLIENT, 3, self.plan, 1, 5, cleanup=cleanup)
    def test_actual_shaped_waiting_trigger_resolves_exact_stop_oid_by_cloid(self):
        result = self.resolve()
        self.assertEqual(result[1], {62205898480, 62205898481})
        self.assertIn(('orderStatus', dict(user=CLIENT, oid=self.fixture.stop_cloid)), self.calls)
    def test_resting_stop_ack_also_requires_same_fresh_lookup(self):
        self.fixture.events[1]['reply']['response']['data']['statuses'][1] = dict(resting=dict(oid=62205898481))
        self.assertEqual(self.resolve()[1], {62205898480,62205898481})
    def test_status_lookup_wrong_oid_refuses(self):
        self.stop_status['order']['order']['oid'] += 1
        with self.assertRaises(RuntimeError): self.resolve()
    def test_all_frontend_wire_mutants_refuse(self):
        mutations = [('cloid','0x7a67'+'f'*28), ('coin','ETH'), ('side','B'), ('sz','0.00019'),
                     ('triggerPx','80735'), ('limitPx','72661'), ('isTrigger',False), ('reduceOnly',False),
                     ('orderType','Take Profit Market'), ('triggerCondition','Price above 80734')]
        original = copy.deepcopy(self.orders)
        for key,value in mutations:
            with self.subTest(key=key):
                self.orders = copy.deepcopy(original);self.orders[0][key]=value
                with self.assertRaises(RuntimeError): self.resolve()
        self.orders = original
    def test_all_lookup_wire_mutants_refuse(self):
        original = copy.deepcopy(self.stop_status)
        for key,value in [('cloid','0x7a67'+'e'*28),('coin','ETH'),('side','B'),('sz','0.00017'),
                          ('triggerPx','80733'),('limitPx','72659'),('isTrigger',False),('reduceOnly',False),
                          ('orderType','Stop Limit'),('triggerCondition','Price above 80734')]:
            with self.subTest(key=key):
                self.stop_status=copy.deepcopy(original);self.stop_status['order']['order'][key]=value
                with self.assertRaises(RuntimeError):self.resolve()
        self.stop_status=original
    def test_stop_lookup_unknown_closed_or_missing_refuses(self):
        original=copy.deepcopy(self.stop_status)
        for value in (dict(status='unknownOid'),dict(status='order',order=dict(status='filled',order=original['order']['order'])),dict(status='order',order={})):
            with self.subTest(value=value):
                self.stop_status=value
                with self.assertRaises(RuntimeError):self.resolve()
    def test_duplicate_frontend_stop_refuses(self):
        self.orders.append(copy.deepcopy(self.orders[0]))
        with self.assertRaises(RuntimeError):self.resolve()
    def test_missing_frontend_stop_with_live_position_refuses(self):
        self.orders=[]
        with self.assertRaises(RuntimeError):self.resolve()
    def test_unrelated_open_order_refuses(self):
        self.orders.append(dict(oid=999,coin='BTC',cloid='0x'+'f'*32))
        with self.assertRaises(RuntimeError):self.resolve(cleanup=True)
    def test_wrong_client_refuses(self):
        self.fixture.decision['client']='0x'+'e'*40
        with self.assertRaises(RuntimeError):self.resolve()
    def test_forwarded_entry_wrong_asset_side_limit_refuses(self):
        original=copy.deepcopy(self.fixture.entry)
        for key,value in [('a',4),('b',False),('p','82547')]:
            with self.subTest(key=key):
                self.fixture.entry.update(original);self.fixture.entry[key]=value
                with self.assertRaises(RuntimeError):self.resolve()
        self.fixture.entry.update(original)
    def test_unacknowledged_or_unknown_deferred_stop_refuses(self):
        original=copy.deepcopy(self.fixture.events[1])
        for stop_ack in ('waitingForFill','success','unknown',dict(resting=dict(oid=999)),dict(error='no stop')):
            with self.subTest(stop_ack=stop_ack):
                self.fixture.events[1]=copy.deepcopy(original)
                self.fixture.events[1]['reply']['response']['data']['statuses'][1]=stop_ack
                with self.assertRaises(RuntimeError):self.resolve()
        self.fixture.events[1]=original
    def test_wrong_entry_ack_oid_or_cloid_refuses(self):
        filled=self.fixture.events[1]['reply']['response']['data']['statuses'][0]['filled']
        original=copy.deepcopy(filled)
        for key,value in [('oid',999),('cloid','0x7a6d'+'f'*28)]:
            with self.subTest(key=key):
                filled.update(original);filled[key]=value
                with self.assertRaises(RuntimeError):self.resolve()
    def test_failed_sent_or_duplicate_order_ack_refuses(self):
        self.fixture.events[1]['ok']=False
        with self.assertRaises(RuntimeError):self.resolve()
        self.fixture.events[1]['ok']=True;self.fixture.events.append(copy.deepcopy(self.fixture.events[1]))
        with self.assertRaises(RuntimeError):self.resolve()
    def test_partial_fill_does_not_receive_complete_journey_credit(self):
        self.fills[0]['sz']='0.00017';self.positions[0].update(szi='0.00017',positionValue='14.00562')
        with self.assertRaises(RuntimeError):self.resolve()
        self.assertEqual(self.resolve(cleanup=True)[1],{62205898480,62205898481})
    def resting(self):
        self.positions=[];self.fills=[]
        order=dict(oid=62205898480,coin='BTC',side='B',sz='0.00018',limitPx='82546.0',cloid=self.fixture.cloid,
                   isTrigger=False,reduceOnly=False,orderType='Limit')
        self.orders=[order];self.entry_status=dict(status='order',order=dict(status='open',order=copy.deepcopy(order)))
        self.fixture.events[1]['reply']['response']['data']['statuses']=[dict(resting=dict(oid=62205898480)),'waitingForFill']
    def test_cleanup_only_resting_entry_proves_only_exact_opening_oid(self):
        self.resting();result=self.resolve(cleanup=True)
        self.assertEqual(result[1],{62205898480});self.assertEqual(result[3],Decimal('0'))
        self.assertNotIn(('orderStatus',dict(user=CLIENT,oid=self.fixture.stop_cloid)),self.calls)
        with self.assertRaises(RuntimeError):self.resolve()
    def test_resting_cleanup_wire_mutants_refuse(self):
        self.resting();original=copy.deepcopy(self.orders)
        for key,value in [('cloid','0x7a6d'+'f'*28),('side','A'),('coin','ETH'),('sz','0.00019'),('limitPx','82547'),('reduceOnly',True),('isTrigger',True),('orderType','Stop Market')]:
            with self.subTest(key=key):
                self.orders=copy.deepcopy(original);self.orders[0][key]=value
                with self.assertRaises(RuntimeError):self.resolve(cleanup=True)
    def test_resting_cleanup_unknown_ack_and_live_position_refuse(self):
        self.resting();self.fixture.events[1]['reply']['response']['data']['statuses'][1]='unknown'
        with self.assertRaises(RuntimeError):self.resolve(cleanup=True)
        self.fixture.events[1]['reply']['response']['data']['statuses'][1]='waitingForFill'
        self.positions=[dict(coin='ETH',szi='1')]
        with self.assertRaises(RuntimeError):self.resolve(cleanup=True)


class PublicWalletBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=str(Path('/tmp').resolve()))
        self.home = Path(self.temp.name) / 'home'; self.home.mkdir(mode=0o700)
        self.path = self.home / 'guard.toml'
        self.args = SimpleNamespace(account=CLIENT, api_wallet='0x' + 'd' * 40, port=18547)
        self.raw = ('mode="testnet"\nnetwork="testnet"\nallow_mainnet=false\naccount="' + CLIENT
                    + '"\nlisten="127.0.0.1:18547"\n[auth]\nclients=["' + CLIENT
                    + '"]\n[policy]\nmax_trading_equity_usd="40"\n')
        self.write(self.raw)

    def write(self, raw):
        self.path.write_text(raw); self.path.chmod(0o600)

    def tearDown(self): self.temp.cleanup()

    def test_missing_root_wallet_gets_exactly_one_public_setting_and_all_else_preserved(self):
        before = j.tomllib.loads(self.raw)
        after = j.bind_public_api_wallet(self.args, self.home)
        self.assertEqual(after, dict(before, api_wallet=self.args.api_wallet))
        self.assertEqual(self.path.read_text(), 'api_wallet = "' + self.args.api_wallet + '"\n' + self.raw)
        self.assertEqual(j.tomllib.loads(self.path.read_text())['api_wallet'], self.args.api_wallet)

    def test_missing_or_invalid_public_argument_refuses_without_writing(self):
        for value in (None, '', '0x123', '0x' + 'd' * 64):
            self.args.api_wallet = value
            with self.assertRaises(RuntimeError): j.bind_public_api_wallet(self.args, self.home)
            self.assertEqual(self.path.read_text(), self.raw)

    def test_existing_correct_or_wrong_wallet_is_never_overwritten(self):
        for value in (self.args.api_wallet, '0x' + 'e' * 40):
            raw = 'api_wallet="' + value + '"\n' + self.raw; self.write(raw)
            with self.assertRaises(RuntimeError): j.bind_public_api_wallet(self.args, self.home)
            self.assertEqual(self.path.read_text(), raw)

    def test_duplicate_root_wallet_refused_without_writing(self):
        raw = ('api_wallet="' + self.args.api_wallet + '"\n') * 2 + self.raw; self.write(raw)
        with self.assertRaises(j.tomllib.TOMLDecodeError): j.bind_public_api_wallet(self.args, self.home)
        self.assertEqual(self.path.read_text(), raw)

    def test_unsafe_mode_symlink_or_hardlink_refused(self):
        self.path.chmod(0o644)
        with self.assertRaises(RuntimeError): j.bind_public_api_wallet(self.args, self.home)
        self.path.chmod(0o600)
        alias = self.home / 'linked'; os.link(self.path, alias)
        with self.assertRaises(RuntimeError): j.bind_public_api_wallet(self.args, self.home)
        alias.unlink()
        self.path.rename(alias); self.path.symlink_to(alias)
        with self.assertRaises(RuntimeError): j.bind_public_api_wallet(self.args, self.home)
        self.assertEqual(alias.read_text(), self.raw)

    def test_existing_config_bindings_cannot_drift(self):
        for old, new in [('mode="testnet"', 'mode="paper"'), ('network="testnet"', 'network="mainnet"'),
                         ('allow_mainnet=false', 'allow_mainnet=true'), (CLIENT + '"\nlisten', '0x' + 'e' * 40 + '"\nlisten'),
                         ('127.0.0.1:18547', '0.0.0.0:18547'), ('clients=["' + CLIENT + '"]', 'clients=[]')]:
            raw = self.raw.replace(old, new); self.write(raw)
            with self.subTest(old=old), self.assertRaises(RuntimeError): j.bind_public_api_wallet(self.args, self.home)
            self.assertEqual(self.path.read_text(), raw)


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=str(Path('/tmp').resolve()))
        base = Path(self.temp.name)
        assets = base / 'assets'; assets.mkdir(mode=0o700)
        binary = base / 'guard'; binary.write_bytes(b'offline fixture never executed'); binary.chmod(0o500)
        arch = {'arm64': 'arm64', 'aarch64': 'arm64', 'x86_64': 'amd64'}[os.uname().machine]
        system = {'Darwin': 'darwin', 'Linux': 'linux'}[os.uname().sysname]
        archive = assets / f'zunder-guard-v1.0.1-{system}-{arch}.tar.gz'
        with tarfile.open(archive, 'w:gz') as out:
            member = tarfile.TarInfo('zunder-guard'); member.size = binary.stat().st_size
            out.addfile(member, io.BytesIO(binary.read_bytes()))
        manifest = assets / 'SHA256SUMS'
        manifest.write_text(j.digest(archive) + '  ' + archive.name + '\n')
        (assets / '.verified-release-source.json').write_text(json.dumps(dict(tag='v1.0.1', source='a' * 40)))
        self.pause = base / 'pause.json'
        now = datetime.now(timezone.utc)
        self.value = dict(tag='v1.0.1', source='a' * 40, account_sha256=hashlib.sha256(CLIENT.encode()).hexdigest(),
                          runner_stopped_confirmed=True, exclusive_account_confirmed=True, testnet_orders_approved=True,
                          max_notional_usdc='40', observed_at=now.isoformat(), expires_at=(now + timedelta(minutes=15)).isoformat())
        self.write_pause()
        for path in assets.iterdir(): path.chmod(0o600)
        self.args = SimpleNamespace(tag='v1.0.1', source='a' * 40, account=CLIENT, api_wallet='0x' + 'd' * 40,
                                    assets=assets, binary=binary,
                                    pause=self.pause, work=base / 'fresh', manifest_sha256=j.digest(manifest))

    def write_pause(self):
        self.pause.write_text(json.dumps(self.value)); self.pause.chmod(0o600)

    def tearDown(self): self.temp.cleanup()

    def test_exact_archive_byte_binding_and_fresh_pause_accepted_offline(self):
        result = j.binding(self.args)
        self.assertEqual(result['binary_sha256'], j.digest(self.args.binary))

    def test_old_release_not_fallback(self):
        self.args.tag = 'v1.0.0'
        with self.assertRaises(RuntimeError): j.binding(self.args)

    def test_substituted_source_build_refused(self):
        self.args.binary.chmod(0o700); self.args.binary.write_bytes(b'other offline bytes')
        with self.assertRaises(RuntimeError): j.binding(self.args)

    def test_mutated_manifest_refused(self):
        (self.args.assets / 'SHA256SUMS').write_text('changed')
        with self.assertRaises(RuntimeError): j.binding(self.args)

    def test_runner_not_paused_refused(self):
        self.value['runner_stopped_confirmed'] = False; self.write_pause()
        with self.assertRaises(RuntimeError): j.binding(self.args)

    def test_exclusive_account_not_confirmed_refused(self):
        self.value['exclusive_account_confirmed'] = False; self.write_pause()
        with self.assertRaises(RuntimeError): j.binding(self.args)

    def test_unapproved_orders_refused(self):
        self.value['testnet_orders_approved'] = False; self.write_pause()
        with self.assertRaises(RuntimeError): j.binding(self.args)

    def test_expired_or_future_pause_refused(self):
        for observed in (datetime.now(timezone.utc) - timedelta(hours=1), datetime.now(timezone.utc) + timedelta(minutes=1)):
            with self.subTest(observed=observed):
                self.value['observed_at'] = observed.isoformat(); self.write_pause()
                with self.assertRaises(RuntimeError): j.binding(self.args)

    def test_source_marker_mismatch_refused(self):
        (self.args.assets / '.verified-release-source.json').write_text(json.dumps(dict(tag='v1.0.1', source='c' * 40)))
        with self.assertRaises(RuntimeError): j.binding(self.args)


class NetworkTests(unittest.TestCase):
    def test_no_exchange_endpoint_in_read_allowlist(self):
        reads = j.Reads(CLIENT)
        with patch.object(reads, 'json') as request:
            with self.assertRaises(RuntimeError): reads.info('exchange')
            request.assert_not_called()

    def test_literal_public_network_is_only_testnet(self):
        self.assertEqual(j.INFO, 'https://api.hyperliquid-testnet.xyz/info')

    def test_redirects_refused(self):
        with self.assertRaises(RuntimeError): j.NoRedirect().redirect_request(None, None, None)

    def test_mainnet_paper_and_presync_status_refused(self):
        args = SimpleNamespace(account=CLIENT, tag='v1.0.1')
        for value in (dict(mode='mainnet'), dict(mode='paper'), dict(mode='testnet', network='testnet', account=CLIENT, version='1.0.1', risk=dict(state='active', journal_ready=True), journal_broken=False, killed=None, last_sync_ms=None)):
            reads = SimpleNamespace(json=lambda url: value)
            with self.subTest(value=value), self.assertRaises(RuntimeError): j.status(reads, 'http://127.0.0.1:18547', args)


class WeightedReadTests(unittest.TestCase):
    class Clock:
        def __init__(self): self.now = 0.0; self.waits = []
        def clock(self): return self.now
        def sleep(self, seconds): self.waits.append(seconds); self.now += seconds

    def make(self):
        clock = self.Clock(); return clock, j.WeightedReads(clock.clock, clock.sleep)

    def test_empty_bucket_waits_before_first_request(self):
        clock, bucket = self.make(); bucket.acquire(20)
        self.assertAlmostEqual(clock.now, 2.0)
        self.assertEqual(list(bucket.sent), [(2.0, 20)])

    def test_cheap_and_expensive_reads_have_actual_weighted_spacing(self):
        clock, bucket = self.make(); bucket.acquire(2); self.assertAlmostEqual(clock.now, .2)
        bucket.acquire(20); self.assertAlmostEqual(clock.now, 2.2)
        bucket.acquire(120); self.assertAlmostEqual(clock.now, 14.2)

    def test_idle_refill_cannot_credit_more_than_bounded_capacity(self):
        clock, bucket = self.make(); clock.now = 1000
        bucket.acquire(120); before = clock.now; bucket.acquire(20)
        self.assertAlmostEqual(clock.now - before, 2)

    def test_rolling_window_never_exceeds_600_after_idle_or_cost_changes(self):
        clock, bucket = self.make(); history = []
        for index, weight in enumerate(([120] + [20, 2] * 90 + [120] * 8) * 3):
            if index % 37 == 0: clock.now += 90
            bucket.acquire(weight); history.append((clock.now, weight))
            self.assertLessEqual(sum(cost for at, cost in history if at > clock.now - 60), 600)

    def test_rolling_window_stops_plain_token_bucket_extra_burst(self):
        clock, bucket = self.make(); clock.now = 100
        for _ in range(5): bucket.acquire(120)
        self.assertEqual(bucket.total, 600)
        bucket.acquire(20)
        self.assertGreater(clock.now, 160)

    def test_deadline_refuses_before_transmission_or_sleep(self):
        clock, bucket = self.make()
        with self.assertRaises(RuntimeError): bucket.acquire(120, deadline=21)
        self.assertEqual(clock.waits, []); self.assertEqual(list(bucket.sent), [])

    def test_invalid_weights_refused(self):
        clock, bucket = self.make()
        for value in (0, -1, 121, True, 2.0, '20'):
            with self.subTest(value=value), self.assertRaises(RuntimeError): bucket.acquire(value)
        self.assertEqual(clock.waits, [])

    def test_official_weights_and_fills_worst_case_precharge(self):
        self.assertEqual(j.READ_WEIGHTS['clearinghouseState'], 2)
        self.assertEqual(j.READ_WEIGHTS['frontendOpenOrders'], 20)
        self.assertEqual(j.READ_WEIGHTS['userAbstraction'], 20)
        self.assertEqual(j.READ_WEIGHTS['perpDexs'], 20)
        self.assertEqual(j.READ_WEIGHTS['userFillsByTime'], 120)
        self.assertNotIn('openOrders', j.READ_WEIGHTS)

    def test_request_type_cannot_override_read_allowlist(self):
        reads = j.Reads(CLIENT)
        with patch.object(reads, 'json') as request:
            with self.assertRaises(RuntimeError): reads.info('meta', type='exchange')
            request.assert_not_called()

    def test_failed_request_is_charged_and_never_retried(self):
        reads = j.Reads(CLIENT); clock, reads.budget = self.make()
        with patch.object(reads, 'json', side_effect=OSError('offline')) as request:
            with self.assertRaises(OSError): reads.info('meta')
            self.assertEqual(request.call_count, 1)
            self.assertEqual(reads.budget.total, 20)


class InventoryTests(unittest.TestCase):
    def inventory(self, count=268): return [None] + [dict(name='dex' + str(i)) for i in range(1, count)]
    def state(self): return dict(assetPositions=[], marginSummary=dict(accountValue='100'))
    def reads(self, values=None, state=None, orders=None, after=None):
        reads = j.Reads(CLIENT); calls = []
        values = self.inventory() if values is None else values
        state = self.state() if state is None else state
        orders = [] if orders is None else orders
        inventory_calls = 0
        def info(kind, **fields):
            nonlocal inventory_calls
            calls.append((kind, fields))
            if kind == 'userAbstraction': return 'disabled'
            if kind == 'perpDexs':
                inventory_calls += 1
                return values if inventory_calls == 1 or after is None else after
            if kind == 'clearinghouseState': return copy.deepcopy(state)
            if kind == 'frontendOpenOrders': return copy.deepcopy(orders)
            raise AssertionError('unexpected read')
        reads.info = info
        return reads, calls

    def test_all_268_dexes_read_twice_and_complete_evidence_bound(self):
        reads, calls = self.reads(); self.assertTrue(reads.flat_all())
        for kind in ('clearinghouseState', 'frontendOpenOrders'):
            fields = [fields for name, fields in calls if name == kind]
            self.assertEqual(len(fields), 268)
            self.assertEqual([row.get('dex', '') for row in fields], reads.flat_observation['dexes'])
            self.assertTrue(all(row['user'] == CLIENT for row in fields))
        self.assertEqual(len(reads.flat_observation['observations']), 268)
        self.assertEqual(sum(kind == 'perpDexs' for kind, _ in calls), 2)

    def test_512_inventory_boundary_accepted_513_refused(self):
        self.assertEqual(len(j.dex_inventory(self.inventory(512))), 512)
        with self.assertRaises(RuntimeError): j.dex_inventory(self.inventory(513))

    def test_empty_missing_main_or_malformed_inventory_refused(self):
        for value in (None, [], [dict(name='bad')], [None, None], [None, 'name'],
                      [None, {}], [None, dict(name=1)], [None, dict(name=True)],
                      [None, dict(name='')], [None, dict(name='a\nb')],
                      [None, dict(name='x' * 129)]):
            with self.subTest(value=value), self.assertRaises(RuntimeError): j.dex_inventory(value)

    def test_duplicate_dexes_refused_before_any_holdings_read(self):
        reads, calls = self.reads([None, dict(name='a'), dict(name='a')])
        with self.assertRaises(RuntimeError): reads.flat_all()
        self.assertFalse(any(kind == 'clearinghouseState' for kind, _ in calls))
        self.assertIsNone(reads.flat_observation)

    def test_inventory_drift_refuses_after_all_original_reads(self):
        reads, calls = self.reads(after=self.inventory(269))
        with self.assertRaises(RuntimeError): reads.flat_all()
        self.assertEqual(sum(kind == 'clearinghouseState' for kind, _ in calls), 268)
        self.assertIsNone(reads.flat_observation)

    def test_omitted_or_reordered_inventory_at_end_refused(self):
        for after in (self.inventory(267), [None] + list(reversed(self.inventory()[1:]))):
            reads, calls = self.reads(after=after)
            with self.assertRaises(RuntimeError): reads.flat_all()
            self.assertIsNone(reads.flat_observation)

    def test_long_short_and_tiny_positions_any_dex_refuse(self):
        for size in ('1', '-1', '0.000000000000001'):
            reads, calls = self.reads(); original = reads.info
            def info(kind, **fields):
                if kind == 'clearinghouseState' and fields.get('dex') == 'dex267':
                    return dict(assetPositions=[dict(position=dict(coin='dex267:COIN', szi=size))],
                                marginSummary=dict(accountValue='100'))
                return original(kind, **fields)
            reads.info = info
            with self.subTest(size=size), self.assertRaises(RuntimeError): reads.flat_all()
            self.assertIsNone(reads.flat_observation)

    def test_trigger_order_zero_size_or_unreadable_order_any_dex_refuses(self):
        for order in (dict(isTrigger=True, sz='0'), dict(sz='1'), {}):
            reads, calls = self.reads(); original = reads.info
            def info(kind, **fields):
                if kind == 'frontendOpenOrders' and fields.get('dex') == 'dex267': return [order]
                return original(kind, **fields)
            reads.info = info
            with self.subTest(order=order), self.assertRaises(RuntimeError): reads.flat_all()
            self.assertIsNone(reads.flat_observation)

    def test_missing_last_dex_response_cannot_produce_partial_credit(self):
        reads, calls = self.reads(); original = reads.info
        def info(kind, **fields):
            if kind == 'clearinghouseState' and fields.get('dex') == 'dex267': return None
            return original(kind, **fields)
        reads.info = info
        with self.assertRaises(RuntimeError): reads.flat_all()
        self.assertIsNone(reads.flat_observation)

    def test_malformed_holdings_refused(self):
        states = [[], {}, dict(assetPositions={}, marginSummary=dict(accountValue='1')),
                  dict(assetPositions=[{}], marginSummary=dict(accountValue='1')),
                  dict(assetPositions=[dict(position=dict(coin='BTC', szi=0))], marginSummary=dict(accountValue='1')),
                  dict(assetPositions=[], marginSummary=dict(accountValue=1)),
                  dict(assetPositions=[], marginSummary={})]
        for state in states:
            reads, _ = self.reads(state=state)
            with self.subTest(state=state), self.assertRaises(RuntimeError): reads.flat_all()
            self.assertIsNone(reads.flat_observation)
        reads, _ = self.reads(orders={})
        with self.assertRaises(RuntimeError): reads.flat_all()

    def test_zero_equity_main_dex_refused_without_funding(self):
        reads, _ = self.reads(state=dict(assetPositions=[], marginSummary=dict(accountValue='0')))
        with self.assertRaises(RuntimeError): reads.flat_all()
        self.assertIsNone(reads.flat_observation)

    def test_failed_second_scan_does_not_reuse_old_pass(self):
        reads, _ = self.reads(); reads.flat_all(); self.assertIsNotNone(reads.flat_observation)
        reads.info = Mock(side_effect=OSError('offline'))
        with self.assertRaises(OSError): reads.flat_all()
        self.assertIsNone(reads.flat_observation)


class ParentFlatTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=str(Path('/tmp').resolve())); self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.path, self.pause = base / 'flat.json', base / 'pause.json'
        now = datetime.now(timezone.utc)
        def when(seconds): return (now + timedelta(seconds=seconds)).isoformat().replace('+00:00', 'Z')
        names = ['', 'dex1']
        self.value = dict(schema=1, kind='actual-complete-testnet-flat', network='testnet', tag='v1.0.1',
                          source='a' * 40, manifest_sha256='b' * 64,
                          account_sha256=hashlib.sha256(CLIENT.lower().encode()).hexdigest(),
                          runner_stop_receipt_sha256='c' * 64, started_at=when(-600), finished_at=when(-10),
                          user_abstraction='disabled', dexes=names, inventory_sha256=j.json_hash(names),
                          inventory_before_sha256='d' * 64, inventory_after_sha256='d' * 64,
                          observations=[dict(dex=name, observed_at=when(-20 + index), positions=0, open_orders=0,
                              positive_equity=True, clearinghouse_sha256='e' * 64, frontend_open_orders_sha256='f' * 64)
                              for index, name in enumerate(names)])
        self.pause_value = dict(observed_at=when(-5), runner_stop_receipt_sha256='c' * 64)
        self.args = SimpleNamespace(preflight_flat=self.path, pause=self.pause, tag='v1.0.1', source='a' * 40,
                                    manifest_sha256='b' * 64, account=CLIENT)
        self.write()

    def write(self):
        self.path.write_text(json.dumps(self.value)); self.path.chmod(0o600)
        self.pause_value['complete_flat_receipt_sha256'] = j.digest(self.path)
        self.pause.write_text(json.dumps(self.pause_value)); self.pause.chmod(0o600)

    def test_exact_recent_complete_hash_bound_parent_scan_accepted(self):
        self.assertTrue(j.parent_flat(self.args))

    def test_no_parent_input_preserves_first_real_scan(self):
        self.args.preflight_flat = None; self.assertFalse(j.parent_flat(self.args))

    def test_missing_or_wrong_pause_hash_refuses(self):
        for value in (None, '0' * 64):
            self.pause_value['complete_flat_receipt_sha256'] = value
            self.pause.write_text(json.dumps(self.pause_value))
            with self.assertRaises(RuntimeError): j.parent_flat(self.args)

    def test_network_account_source_tag_manifest_scope_cannot_drift(self):
        for key, value in (('network','mainnet'), ('account_sha256','0'*64), ('source','0'*40),
                           ('tag','v1.0.0'), ('manifest_sha256','0'*64), ('user_abstraction','unifiedAccount')):
            before = copy.deepcopy(self.value); self.value[key] = value; self.write()
            with self.subTest(key=key), self.assertRaises(RuntimeError): j.parent_flat(self.args)
            self.value = before

    def test_nonzero_boolean_or_missing_counts_refuse(self):
        for field, value in (('positions',1), ('open_orders',1), ('positions',False), ('open_orders',None),
                             ('positive_equity',False)):
            before = copy.deepcopy(self.value); self.value['observations'][0][field] = value; self.write()
            with self.subTest(field=field,value=value), self.assertRaises(RuntimeError): j.parent_flat(self.args)
            self.value = before

    def test_missing_duplicate_or_misordered_dex_observations_refuse(self):
        for observations in (self.value['observations'][:-1], self.value['observations'] * 2,
                             list(reversed(self.value['observations']))):
            before = copy.deepcopy(self.value); self.value['observations'] = observations; self.write()
            with self.assertRaises(RuntimeError): j.parent_flat(self.args)
            self.value = before

    def test_inventory_digest_duplicate_missing_main_refuse(self):
        for names in (['dex1'], ['', 'dex1', 'dex1'], ['', 'dex2']):
            before = copy.deepcopy(self.value); self.value['dexes'] = names; self.write()
            with self.subTest(names=names), self.assertRaises(RuntimeError): j.parent_flat(self.args)
            self.value = before

    def test_stale_future_or_overlong_scan_refuses(self):
        now = datetime.now(timezone.utc)
        def when(seconds): return (now + timedelta(seconds=seconds)).isoformat().replace('+00:00','Z')
        for key, value in (('finished_at',when(-121)), ('finished_at',when(5)),
                           ('started_at',when(-901)), ('started_at',when(-800))):
            before = copy.deepcopy(self.value); self.value[key] = value; self.write()
            with self.subTest(key=key,value=value), self.assertRaises(RuntimeError): j.parent_flat(self.args)
            self.value = before

    def test_parent_stop_digest_must_match_fresh_pause(self):
        self.value['runner_stop_receipt_sha256'] = '0' * 64; self.write()
        with self.assertRaises(RuntimeError): j.parent_flat(self.args)

    def test_response_hash_or_timestamp_tampering_refuses(self):
        for field, value in (('clearinghouse_sha256','bad'), ('frontend_open_orders_sha256','bad'),
                             ('observed_at','2020-01-01T00:00:00Z')):
            before = copy.deepcopy(self.value); self.value['observations'][0][field] = value; self.write()
            with self.subTest(field=field), self.assertRaises(RuntimeError): j.parent_flat(self.args)
            self.value = before

    def test_unsafe_parent_file_refused(self):
        self.path.chmod(0o644)
        with self.assertRaises(RuntimeError): j.parent_flat(self.args)


class FastAdoptedPreEntryTests(unittest.TestCase):
    write = ParentFlatTests.write
    def setUp(self):
        ParentFlatTests.setUp(self)
        self.positions=[];self.orders=[];self.equity=Decimal('100');self.calls=[]
        self.before=[None,dict(name='dex1')];self.after=copy.deepcopy(self.before)
        self.abstraction='disabled';self.after_main=lambda:None
        outer=self
        class Reads:
            flat_observation=None
            def info(self,kind,**fields):
                outer.calls.append(kind)
                if kind=='userAbstraction':return outer.abstraction
                if kind=='perpDexs':return copy.deepcopy(outer.before if outer.calls.count(kind)==1 else outer.after)
                raise AssertionError('Unexpected synthetic read.')
            def holdings(self,*,evidence=False):
                outer.calls.append('holdings');outer.after_main()
                observation=dict(dex='',observed_at=j.utc_now(),positions=len(outer.positions),open_orders=len(outer.orders),
                                 positive_equity=outer.equity>0,clearinghouse_sha256='1'*64,frontend_open_orders_sha256='2'*64)
                return copy.deepcopy(outer.positions),copy.deepcopy(outer.orders),outer.equity,observation
        self.reads=Reads()
    def check(self):return j.adopted_pre_entry(self.reads,self.args)
    def test_fresh_main_and_inventory_keeps_original_full_scan_duration(self):
        result=self.check()
        self.assertFalse(result['second_full_scan_performed'])
        self.assertEqual(result['kind'],'adopted-complete-parent-scan-plus-fresh-main-dex-and-inventory')
        self.assertEqual(self.calls,['userAbstraction','perpDexs','holdings','perpDexs'])
        self.assertEqual(self.reads.flat_observation['started_at'],self.value['started_at'])
        self.assertEqual(j.cleanup_reservation(self.reads.flat_observation),710)
    def test_parent_expiry_is_rechecked_after_startup(self):
        self.value['finished_at']=(datetime.now(timezone.utc)-timedelta(seconds=121)).isoformat();self.write()
        with self.assertRaises(RuntimeError):self.check()
        self.assertEqual(self.calls,[])
    def test_parent_must_still_validate_after_fresh_reads(self):
        with patch.object(j,'parent_flat',side_effect=[True,False]):
            with self.assertRaises(RuntimeError):self.check()
    def test_fresh_before_or_after_inventory_change_refuses(self):
        for field in('before','after'):
            with self.subTest(field=field):
                self.calls=[];original=copy.deepcopy(getattr(self,field));setattr(self,field,[None,dict(name='other')])
                with self.assertRaises(RuntimeError):self.check()
                setattr(self,field,original)
    def test_fresh_main_position_or_order_refuses(self):
        for field in('positions','orders'):
            with self.subTest(field=field):
                self.calls=[];setattr(self,field,[dict(synthetic=True)])
                with self.assertRaises(RuntimeError):self.check()
                setattr(self,field,[])
    def test_fresh_nonpositive_equity_refuses(self):
        for value in(Decimal('0'),Decimal('-1')):
            with self.subTest(value=value):
                self.calls=[];self.equity=value
                with self.assertRaises(RuntimeError):self.check()
    def test_fresh_changed_account_mode_refuses(self):
        self.abstraction='unifiedAccount'
        with self.assertRaises(RuntimeError):self.check()
    def test_parent_file_changed_during_main_read_refuses(self):
        self.after_main=lambda:self.path.write_text('{"synthetic":"changed"}')
        with self.assertRaises(RuntimeError):self.check()
    def test_pause_file_changed_during_main_read_refuses(self):
        self.after_main=lambda:self.pause.write_text('{"synthetic":"changed"}')
        with self.assertRaises(RuntimeError):self.check()
    def test_cleanup_reservation_uses_full_count_and_actual_parent_duration(self):
        now=datetime.now(timezone.utc)
        observed=dict(dexes=['']+[str(i)for i in range(267)],started_at=(now-timedelta(seconds=650)).isoformat().replace('+00:00','Z'),finished_at=now.isoformat().replace('+00:00','Z'))
        self.assertEqual(j.cleanup_reservation(observed),770)
        observed['started_at']=(now-timedelta(seconds=100)).isoformat().replace('+00:00','Z')
        self.assertEqual(j.cleanup_reservation(observed),715.6)
    def test_separately_forwarded_wrong_entry_asset_side_and_limit_refuse(self):
        fixture=StopProofTests();fixture.setUp()
        original=copy.deepcopy(fixture.decision['forward']['orders'][0])
        fixture.decision['forward']['orders'][0]=copy.deepcopy(original)
        for field,value in(('a',1),('b',False),('p','100201')):
            with self.subTest(field=field):
                fixture.decision['forward']['orders'][0]=copy.deepcopy(original)
                fixture.decision['forward']['orders'][0][field]=value
                with self.assertRaises(RuntimeError):fixture.check()


if __name__ == '__main__': unittest.main()
